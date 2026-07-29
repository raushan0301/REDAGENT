output "target_public_ip" {
  description = "The public IP address of the vulnerable lab instance to be scanned by RedAgent."
  value       = aws_instance.redagent_target.public_ip
}
