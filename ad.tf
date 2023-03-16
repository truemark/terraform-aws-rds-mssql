resource "aws_iam_role" "ad" {
  count = var.create && var.domain_id == "" ? 0 : 1
  name  = "${lower(var.instance_name)}-active-directory"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "ADAssumeRole"
        Principal = {
          Service = "rds.amazonaws.com"
        }
      },
    ]
  })

}

resource "aws_iam_role_policy_attachment" "ad" {
  count = var.create && var.domain_id == "" ? 0 : 1

  role = aws_iam_role.ad[0].name
  # The actions the role can execute
  policy_arn = data.aws_iam_policy.ad.arn
  # depends_on = [
  #   aws_iam_role.ad
  # ]
}

data "aws_iam_policy" "ad" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSDirectoryServiceAccess"
}
