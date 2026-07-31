variable "aws_region" {
  description = "The AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type for the vulnerable lab target"
  type        = string
  default     = "t3.micro"
}

variable "agent_instance_type" {
  description = "EC2 instance type for the RedAgent attack host"
  type        = string
  default     = "t3.small"
}

variable "allowed_ssh_cidr" {
  description = <<-EOT
    Optional CIDR allowed direct SSH ingress (e.g. "203.0.113.4/32", your own
    IP — never leave this as 0.0.0.0/0). Leave unset (null, the default) to
    disable SSH entirely and use AWS Systems Manager Session Manager instead,
    which needs no inbound ports at all. SSM is the recommended access path.
  EOT
  type        = string
  default     = null
}
