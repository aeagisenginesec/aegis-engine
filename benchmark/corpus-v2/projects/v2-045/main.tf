resource "aws_ecs_service" "frontend" {
  name            = "frontend"
  cluster         = "arn:aws:ecs:us-east-1:123456789012:cluster/prod"
  task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/frontend:1"
  desired_count   = 2

  network_configuration {
    subnets          = ["subnet-0a1b2c3d"]
    security_groups  = ["sg-0a1b2c3d"]
    assign_public_ip = true
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}
