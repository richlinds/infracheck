resource "aws_sqs_queue" "my_queue" {
  name                       = "my-queue"
  visibility_timeout_seconds = 30
}

resource "aws_lambda_function" "my_func" {
  function_name = "my-func"
  runtime       = "python3.14"
}
