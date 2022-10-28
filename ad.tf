# All objects required to hook this db up to Active Directory
resource "aws_db_instance_role_association" "ad" {
  db_instance_identifier = module.db.db_instance_id
  role_arn               = aws_iam_role.ad.arn
  feature_name           = "Directory Service"
}

resource "aws_iam_role" "ad" {
  name = "${lower(var.instance_name)}-active-directory"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "rds.amazonaws.com"
        }
      },
    ]
  })

}

resource "aws_iam_role_policy_attachment" "ad" {
  role = aws_iam_role.ad.name
  # The actions the role can execute
  policy_arn = data.aws_iam_policy.ad.arn
}

data "aws_iam_policy" "ad" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSDirectoryServiceAccess"
}
