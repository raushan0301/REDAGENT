output "target_private_ip" {
  description = "Private IP of the vulnerable lab instance — add this to REDAGENT_SCOPE."
  value       = aws_instance.redagent_target.private_ip
}

output "attack_host_private_ip" {
  description = "Private IP of the RedAgent attack host (where RedAgent itself runs)."
  value       = aws_instance.redagent_attack_host.private_ip
}

output "ssm_connect_target" {
  description = "Command to open a shell on the target — no SSH or inbound ports needed."
  value       = "aws ssm start-session --target ${aws_instance.redagent_target.id}"
}

output "ssm_connect_attack_host" {
  description = "Command to open a shell on the attack host — no SSH or inbound ports needed."
  value       = "aws ssm start-session --target ${aws_instance.redagent_attack_host.id}"
}
