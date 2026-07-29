variable "aws_region" {
  description = "The AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type for the vulnerable lab"
  type        = string
  default     = "t3.micro"
}

variable "allowed_ip" {
  description = "The IP address (CIDR) allowed to access the lab. CHANGE THIS BEFORE DEPLOYING."
  type        = string
  default     = "0.0.0.0/0"
}
