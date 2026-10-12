resource "aws_ecs_task_definition" "worker" {
  family                   = "worker"
  network_mode             = "host"
  requires_compatibilities = ["EC2"]
  container_definitions    = <<JSON
[
  {
    "name": "worker",
    "image": "worker:latest",
    "cpu": 256,
    "memory": 512,
    "essential": true,
    "readonlyRootFilesystem": true
  }
]
JSON
}
