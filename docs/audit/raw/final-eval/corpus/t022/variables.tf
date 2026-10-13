variable "project" {
  type        = string
  description = "Project name prefix"
}

variable "region" {
  type        = string
  description = "AWS region"
}

variable "topic_name" {
  type        = string
  description = "SNS topic name"
}

variable "queue_name" {
  type        = string
  description = "SQS queue name"
}
