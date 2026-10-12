resource "aws_ecs_service" "web" {
  name            = "web"
  cluster         = "arn:aws:ecs:us-east-1:123456789012:cluster/prod"
  task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/web:1"
  desired_count   = 2
  network_configuration {
    subnets          = ["subnet-12345678"]
    assign_public_ip = true
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}
