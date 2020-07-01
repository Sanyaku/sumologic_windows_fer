variable "base_scope" {
  type    = string
  default = "_sourcecategory=OS/Windows*"
}

variable "base_name" {
  type = string
  default = "Windows Security Event Code"
}

resource "sumologic_field_extraction_rule" "WindowsDefaultFields" {
  name = "Windows Default Fields Optimized"
  scope = var.base_scope
  parse_expression = <<-EOT
  parse "EventCode = *;" as EventId nodrop
  | parse "CategoryString = \"*\";" as category nodrop
  | parse "Type = \"*\"" as type nodrop
  | parse "Message = \"*\r" as Description nodrop
  | parse "RecordNumber = *;" as EventRecordID nodrop
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4624" {
  name = "${var.base_name} 4624"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4624"
  EOT
  parse_expression = <<-EOT
  parse "Logon Type:*\r\n" as EventData_LogonType
  | trim(EventData_LogonType)
  | parse "New Logon:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Process Information:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | parse "Network Information:\r\n\tWorkstation Name:*\r\n\tSource Network Address:*\r\n\tSource Port:*\r\n" as EventData_WorkstationName,EventData_IpAddress,EventData_IpPort
  | trim(EventData_WorkstationName) | trim(EventData_IpAddress) | trim(EventData_IpPort)
  | parse "Detailed Authentication Information:\r\n\tLogon Process:*\r\n" as EventData_LogonProcessName
  | trim(EventData_LogonProcessName)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4625" {
  name = "${var.base_name} 4625"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4625"
  EOT
  parse_expression = <<-EOT
  parse "Logon Type:*\r\n" as EventData_LogonType
  | trim(EventData_LogonType)
  | parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,_2,_3,EventData_LogonId
  | trim(EventData_LogonId)
  | parse "Account For Which Logon Failed:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n" as _4,EventData_SubjectUserName,EventData_SubjectDomainName
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName)
  | parse "Failure Information:\r\n\tFailure Reason:*\r\n\tStatus:*\r\n\tSub Status:*\r\n" as EventData_FailureReason,EventData_Status,EventData_SubStatus
  | trim(EventData_FailureReason) | trim(EventData_Status) | trim(EventData_SubStatus)
  | parse "Process Information:\r\n\tCaller Process ID:*\r\n\tCaller Process Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | parse "Network Information:\r\n\tWorkstation Name:*\r\n\tSource Network Address:*\r\n\tSource Port:*\r\n" as EventData_WorkstationName,EventData_IpAddress,EventData_IpPort
  | trim(EventData_WorkstationName) | trim(EventData_IpAddress) | trim(EventData_IpPort)
  | parse "Detailed Authentication Information:\r\n\tLogon Process:*\r\n" as EventData_LogonProcessName
  | trim(EventData_LogonProcessName)
  | fields - _1,_2,_3,_4
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4627" {
  name = "${var.base_name} 4627"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4627"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "New Logon:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n" as _2,EventData_TargetUserName,EventData_TargetDomainName
  | trim(EventData_TargetUserName) | trim(EventData_TargetDomainName)
  | fields - _1,_2
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4648" {
  name = "${var.base_name} 4648"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4648"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Account Whose Credentials Were Used:\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n" as EventData_TargetUserName,EventData_TargetDomainName
  | trim(EventData_TargetUserName) | trim(EventData_TargetDomainName)
  | parse "Process Information:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | parse "Network Information:\r\n\tNetwork Address:*\r\n\tPort:*\r\n" as EventData_IpAddress,EventData_IpPort
  | trim(EventData_IpAddress) | trim(EventData_IpPort)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4656" {
  name = "${var.base_name} 4656"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4656"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Object Name:*\r\n" as EventData_ObjectDN
  | trim(EventData_ObjectDN)
  | parse "Process Information:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4662" {
  name = "${var.base_name} 4662"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4662"
  EOT
  parse_expression = <<-EOT
  parse "Subject :\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Object Name:*\r\n" as EventData_ObjectDN
  | trim(EventData_ObjectDN)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4663" {
  name = "${var.base_name} 4663"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4663"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Object Name:*\r\n" as EventData_ObjectDN
  | trim(EventData_ObjectDN)
  | parse "Process Information:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4670" {
  name = "${var.base_name} 4670"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4670"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Object Name:*\r\n" as EventData_ObjectDN
  | trim(EventData_ObjectDN)
  | parse "Process:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4673" {
  name = "${var.base_name} 4673"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4673"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Process:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4674" {
  name = "${var.base_name} 4674"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4674"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Object Name:*\r\n" as EventData_ObjectDN
  | trim(EventData_ObjectDN)
  | parse "Process Information:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent46788" {
  name = "${var.base_name} 4688"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4688"
  EOT
  parse_expression = <<-EOT
  parse "Creator Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Target Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n" as _2,EventData_TargetUserName,EventData_TargetDomainName
  | trim(EventData_TargetUserName) | trim(EventData_TargetDomainName)
  | parse "Process Information:\r\n\tNew Process ID:*\r\n\tNew Process Name:*\r\n\tToken Elevation Type:*\r\n\tMandatory Label:*\r\n\tCreator Process ID:*\r\n\tCreator Process Name:*\r\n\tProcess Command Line:*\r\n" as EventData_ProcessId,EventData_ProcessName,_3,_4,_5,EventData_ParentProcess,EventData_CommandLine
  | trim(EventData_ProcessId) | trim(EventData_ProcessName) | trim(EventData_ParentProcess) | trim(EventData_CommandLine)
  | fields - _1,_2,_3,_4,_5
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4691" {
  name = "${var.base_name} 4691"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4691"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Object Name:*\r\n" as EventData_ObjectDN
  | trim(EventData_ObjectDN)
  | parse "Process Information:\r\n\tProcess ID:*\r\n" as EventData_ProcessId
  | trim(EventData_ProcessId)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4696" {
  name = "${var.base_name} 4696"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4696"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Process Information:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | parse "New Token Information:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n" as _2,EventData_TargetUserName,EventData_TargetDomainName
  | trim(EventData_TargetUserName) | trim(EventData_TargetDomainName)
  | fields - _1,_2
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4697" {
  name = "${var.base_name} 4697"
  scope = <<-EOT
    ${var.base_scope} "EventCode = 4697"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Service Information:\r\n\tService Name:*\r\n\tService File Name:*\r\n" as EventData_ServiceName,EventData_ServiceFileName
  | trim(EventData_ServiceName) | trim(EventData_ServiceFileName)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEventScheduledTasks" {
  name = "${var.base_name} 4698, 4699, 4700, 4701"
  scope = <<-EOT
  ${var.base_scope} ("EventCode = 4698" OR "EventCode = 4699" OR "EventCode = 4700" OR "EventCode = 4701")
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Task Information:\r\n\tTask Name:*\r\n" as EventData_TaskName
  | trim(EventData_TaskName)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4720" {
  name = "${var.base_name} 4720"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4720"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as EventData_SubjectSecurityId,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectSecurityId) | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "New Account:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n" as EventData_TargetSecurityId,EventData_TargetUserName,EventData_TargetDomainName
  | trim(EventData_TargetSecurityId) | trim(EventData_TargetUserName) | trim(EventData_TargetDomainName)
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent472247244725" {
  name = "${var.base_name} 4722 4724 4725"
  scope = <<-EOT
  ${var.base_scope} ("EventCode = 4722" OR "EventCode = 4724" OR "EventCode = 4725")
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as EventData_SubjectSecurityId,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectSecurityId) | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Target Account:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\";" as EventData_TargetSecurityId,EventData_TargetUserName,EventData_TargetDomainName
  | trim(EventData_TargetSecurityId) | trim(EventData_TargetUserName) | trim(EventData_TargetDomainName)
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEventAccounts" {
  name = "${var.base_name} 4723 4726 4738"
  scope = <<-EOT
  ${var.base_scope} ("EventCode = 4723" OR "EventCode = 4726" OR "EventCode = 4738")
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as EventData_SubjectSecurityId,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectSecurityId) | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Target Account:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n" as EventData_TargetSecurityId,EventData_TargetUserName,EventData_TargetDomainName
  | trim(EventData_TargetSecurityId) | trim(EventData_TargetUserName) | trim(EventData_TargetDomainName)
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEventGroupCreation" {
  name = "${var.base_name} 4727 4731"
  scope = <<-EOT
  ${var.base_scope} ("EventCode = 4727" OR "EventCode = 4731")
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "New Group:\r\n\tSecurity ID:*\r\n\tGroup Name:*\r\n" as _2,EventData_GroupName
  | trim(EventData_GroupName)
  | fields - _1,_2
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEventGroupMgmt" {
  name = "${var.base_name} 4728 4729 4732 4733 4734 4735 4737 4755 4756 4757 4761"
  scope = <<-EOT
  ${var.base_scope} ("EventCode = 4728" OR "EventCode = 4729" OR "EventCode = 4732" OR "EventCode = 4733" OR "EventCode = 4734" OR "EventCode = 4735" OR "EventCode = 4737" OR "EventCode = 4755" OR "EventCode = 4756" OR "EventCode = 4757" OR "EventCode = 4761")
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Group:\r\n\tSecurity ID:*\r\n\tGroup Name:*\r\n" as _2,EventData_GroupName
  | trim(EventData_GroupName)
  | fields - _1,_2
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4740" {
  name = "${var.base_name} 4740"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4740"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Additional Information:\r\n\tCaller Computer Name:*\"" as EventData_CallerComputer
  | trim(EventData_CallerComputer)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEventKerberos" {
  name = "${var.base_name} 4768 4769 4770"
  scope = <<-EOT
  ${var.base_scope} ("EventCode = 4768" OR "EventCode = 4769" OR "EventCode = 4770")
  EOT
  parse_expression = <<-EOT
  parse "Account Information:\r\n\tAccount Name:*\r\n" as EventData_SubjectUserName
  | trim(EventData_SubjectUserName)
  | parse "Network Information:\r\n\tClient Address:*::ffff:*\r\n\tClient Port:*\r\n" as _1,EventData_IpAddress,EventData_IpPort
  | trim(EventData_IpAddress) | trim(EventData_IpPort)
  | parse "Ticket Encryption Type:*\r\n" as EventData_TicketEncryption
  | trim(EventData_TicketEncryption)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4771" {
  name = "${var.base_name} 4771"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4771"
  EOT
  parse_expression = <<-EOT
  parse "Account Information:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n" as _1,EventData_SubjectUserName
  | trim(EventData_SubjectUserName)
  | parse "Network Information:\r\n\tClient Address:*::ffff:*\r\n\tClient Port:*\r\n" as _2,EventData_IpAddress,EventData_IpPort
  | trim(EventData_IpAddress) | trim(EventData_IpPort)
  | parse "Failure Code:*\r\n" as EventData_FailureCode
  | trim(EventData_FailureCode)
  | fields - _1,_2
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4776" {
  name = "${var.base_name} 4776"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4776"
  EOT
  parse_expression = <<-EOT
  parse "Source Workstation:*\r\n" as EventData_WorkstationName
  | trim(EventData_WorkstationName)
  | parse "Error Code:*\"" as EventData_FailureCode
  | trim(EventData_FailureCode)
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent4799" {
  name = "${var.base_name} 4799"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 4799"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Group:\r\n\tSecurity ID:*\r\n\tGroup Name:*\r\n" as _2,EventData_GroupName
  | trim(EventData_GroupName)
  | parse "Process Information:\r\n\tProcess ID:*\r\n\tProcess Name:*\"" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | fields - _1,_2
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent49074911" {
  name = "${var.base_name} 4907 4911"
  scope = <<-EOT
  ${var.base_scope} ("EventCode = 4907" OR "EventCode = 4911")
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Process Information:\r\n\tProcess ID:*\r\n\tProcess Name:*\r\n" as EventData_ProcessId,EventData_ProcessName
  | trim(EventData_ProcessId) | trim(EventData_ProcessName)
  | parse "Object Name:*\r\n" as EventData_ObjectDN
  | trim(EventData_ObjectDN)
  | fields - _1
  EOT
  enabled = true
}

resource "sumologic_field_extraction_rule" "WindowsEvent5140" {
  name = "${var.base_name} 5140"
  scope = <<-EOT
  ${var.base_scope} "EventCode = 5140"
  EOT
  parse_expression = <<-EOT
  parse "Subject:\r\n\tSecurity ID:*\r\n\tAccount Name:*\r\n\tAccount Domain:*\r\n\tLogon ID:*\r\n" as _1,EventData_SubjectUserName,EventData_SubjectDomainName,EventData_LogonId
  | trim(EventData_SubjectUserName) | trim(EventData_SubjectDomainName) | trim(EventData_LogonId)
  | parse "Network Information:*\r\n\tObject Type:*\r\n\tSource Address:*\r\n\tSource Port:*\r\n" as _2,_3,EventData_IpAddress,EventData_IpPort
  | trim(EventData_IpAddress) | trim(EventData_IpPort)
  | parse "Share Name:*\r\n" as EventData_ShareName
  | trim(EventData_ShareName)
  | fields - _1,_2,_3
  EOT
  enabled = true
}
