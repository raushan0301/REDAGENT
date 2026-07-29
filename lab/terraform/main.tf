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

# Fetch the latest Ubuntu 22.04 LTS AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# Networking
resource "aws_vpc" "redagent_lab_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "redagent-lab-vpc"
  }
}

resource "aws_subnet" "redagent_lab_subnet" {
  vpc_id                  = aws_vpc.redagent_lab_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  tags = {
    Name = "redagent-lab-subnet"
  }
}

resource "aws_internet_gateway" "redagent_lab_igw" {
  vpc_id = aws_vpc.redagent_lab_vpc.id
  tags = {
    Name = "redagent-lab-igw"
  }
}

resource "aws_route_table" "redagent_lab_rt" {
  vpc_id = aws_vpc.redagent_lab_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.redagent_lab_igw.id
  }

  tags = {
    Name = "redagent-lab-rt"
  }
}

resource "aws_route_table_association" "redagent_lab_rta" {
  subnet_id      = aws_subnet.redagent_lab_subnet.id
  route_table_id = aws_route_table.redagent_lab_rt.id
}

# Security Group
resource "aws_security_group" "redagent_lab_sg" {
  name        = "redagent-lab-sg"
  description = "Allow inbound scanning traffic for RedAgent lab"
  vpc_id      = aws_vpc.redagent_lab_vpc.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Custom ports for vulnerable apps (e.g., 8080, 8443, etc.)
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "redagent-lab-sg"
  }
}

# EC2 Instance
resource "aws_instance" "redagent_target" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  subnet_id     = aws_subnet.redagent_lab_subnet.id
  vpc_security_group_ids = [aws_security_group.redagent_lab_sg.id]

  # Install Docker and run a vulnerable container (CVE-2017-7494/Samba as an example)
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y docker.io
              systemctl start docker
              systemctl enable docker
              
              # Pull and run a vulnerable target. 
              # Examples: 
              # - bkimminich/juice-shop (OWASP Juice Shop) on 3000 -> 80
              # - vulnerables/cve-2017-7494
              docker run -d -p 80:3000 bkimminich/juice-shop
              EOF

  tags = {
    Name = "redagent-vulnerable-target"
  }
}
