terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Fetch the latest Ubuntu 22.04 LTS AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# ── Networking ───────────────────────────────────────────────────────────
# Isolated lab VPC (SECURITY.md: "isolated AWS VPC private subnet"). The
# target and the RedAgent attack host both live in a PRIVATE subnet with no
# inbound route from the internet — nothing on the internet can initiate a
# connection in. A NAT gateway in a small public subnet gives outbound-only
# access for package installs (apt/docker pull), which is a one-way door.

resource "aws_vpc" "redagent_lab_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "redagent-lab-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.redagent_lab_vpc.id
  cidr_block              = "10.0.0.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "redagent-lab-public" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.redagent_lab_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "redagent-lab-private" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.redagent_lab_vpc.id
  tags   = { Name = "redagent-lab-igw" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "redagent-lab-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  tags          = { Name = "redagent-lab-nat" }
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.redagent_lab_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "redagent-lab-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.redagent_lab_vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "redagent-lab-private-rt" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# ── Security group ───────────────────────────────────────────────────────
# No inbound from the internet by default. Management access is via AWS
# Systems Manager Session Manager (no open ports needed). Direct SSH is
# opt-in only, gated behind var.allowed_ssh_cidr — never defaults to open.

resource "aws_security_group" "redagent_lab_sg" {
  name        = "redagent-lab-sg"
  description = "RedAgent isolated lab — no inbound internet access by default"
  vpc_id      = aws_vpc.redagent_lab_vpc.id

  dynamic "ingress" {
    for_each = var.allowed_ssh_cidr != null ? [var.allowed_ssh_cidr] : []
    content {
      description = "Optional direct SSH from the operator's own IP"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  # Intra-lab traffic only: attack host <-> targets, within this VPC.
  ingress {
    description = "Intra-VPC traffic (attack host <-> targets)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.redagent_lab_vpc.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "redagent-lab-sg" }
}

# ── SSM access (no inbound ports required) ───────────────────────────────

resource "aws_iam_role" "ssm_role" {
  name = "redagent-lab-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_profile" {
  name = "redagent-lab-ssm-profile"
  role = aws_iam_role.ssm_role.name
}

# ── Vulnerable target — private subnet, no public IP ─────────────────────

resource "aws_instance" "redagent_target" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.redagent_lab_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ssm_profile.name
  associate_public_ip_address = false

  # Install Docker + SSM agent (usually preinstalled on Ubuntu AMIs; the snap
  # install is defensive/idempotent) and run a vulnerable container.
  # Examples: bkimminich/juice-shop (OWASP Juice Shop) on 3000 -> 80
  user_data = <<-EOF
              #!/bin/bash
              snap install amazon-ssm-agent --classic || true
              apt-get update
              apt-get install -y docker.io
              systemctl start docker
              systemctl enable docker
              docker run -d -p 80:3000 bkimminich/juice-shop
              EOF

  tags = { Name = "redagent-vulnerable-target" }
}

# ── Attack host — RedAgent itself runs here, same private subnet ─────────
# Matches the Week 1 lab-setup goal ("Configure Kali Linux EC2 instance as
# attack machine") — using a plain Ubuntu box with the tool belt installed
# rather than a Kali AMI, since Kali's marketplace AMI requires a separate
# subscription. Swap the AMI/user_data for Kali if you have access to one.

resource "aws_instance" "redagent_attack_host" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.agent_instance_type
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.redagent_lab_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ssm_profile.name
  associate_public_ip_address = false

  # Base tooling for RedAgent. Extend with the full tool belt (nuclei,
  # sqlmap, subfinder, Metasploit) as the deployment story matures.
  user_data = <<-EOF
              #!/bin/bash
              snap install amazon-ssm-agent --classic || true
              apt-get update
              apt-get install -y nmap python3-venv python3-pip docker.io
              systemctl start docker
              systemctl enable docker
              EOF

  tags = { Name = "redagent-attack-host" }
}
