$ExcelWorkbookPath = "C:\CloudReplication\Billing\"
$ExcelArchivePath = "C:\CloudReplication\Billing\Archive\"
$ExcelWorkbookTemplate = "C:\CloudReplication\CRS_Billing_Report_Template"
$ChargeComponentId = "A-S00001234"

Function GetDeviceInfo
{
    Param($vmName)
    $SqlServer = "myserver.com"
    $ConnectionString = "Data Source=myserver.com;Initial Catalog=Warehouse;Integrated Security=True;"
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
    $SqlConnection.Open()
    $SqlQuery = "SELECT c.NumberOfCores, m.SizeInMegabytes FROM Device
                 INNER JOIN DeviceCpu c on Device.ID = c.DeviceID
                 INNER JOIN DeviceMemory m on Device.ID = m.DeviceID
                 where Device.Name = @vmname"
    $SqlCommand = $SqlConnection.CreateCommand()
    $SqlCommand.CommandText = $SqlQuery
    [Void]$SqlCommand.Parameters.AddWithValue("@vmname", $vmName)
    $Adapter = New-Object System.Data.SqlClient.SqlDataAdapter $SqlCommand
    $DataSet = New-Object System.Data.DataSet
    
    $Adapter.Fill($DataSet) | out-null
    
    
    $DataTable = $DataSet.Tables[0]
    
    $SqlCommand.Dispose()
    $SqlConnection.Close()
    $SqlConnection.Dispose()

    return $DataTable
}

Function GetYesterdayRecoveryRuns()
{
    $SqlServer = "myserver.com"
    $ConnectionString = "Data Source=myserver.com;Initial Catalog=Portal;Integrated Security=True;"
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
    $SqlConnection.Open()
    $LastMonth = (Get-Date).AddMonths(-1).ToString("yy-MM")
    $SqlQuery = "SELECT * FROM CloudReplicationHistoricalActionLog"
    $DataAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($SqlQuery, $SqlConnection)
    $DataSet = New-Object System.Data.DataSet
    $DataAdapter.Fill($DataSet)
    $SqlConnection.Close()
    
    foreach($row in $DataSet.Tables[0])
    {
        if ($row['StartTime'].ToString("yy-MM") -ne $LastMonth)
        {
            $row.Delete()
        }
        if ($row['DeviceNames'] -eq [DBNull]::Value)
        {
            $row.Delete()
        }
    }
    
    # create excel object
    $Excel = New-Object -ComObject Excel.Application
    $Workbook = $Excel.Workbooks.Open($ExcelWorkbookTemplate)
    $Sheet1 = $Workbook.Worksheets.Item(1)
    $Sheet1.Name = "Daily Report"
    
    # Loop through datatable
    $x = 6
    foreach ($row in $DataSet.Tables[0])
    {
        if ($row['CustomerAccountNumber'] -ne [DBNull]::Value)
        {
            $Devices = $row["DeviceNames"]
            if ($Devices -ne [DBNull]::Value -and $Devices -ne $null) 
            {
                $DeviceList = $Devices.split(",")
                foreach ($Device in $DeviceList)
                {
                    $VMInfo = GetDeviceInfo($Device.Trim())
                    $Sheet1.cells.item($x, 1) = $row['StartTime']
                    $Sheet1.cells.item($x, 2) = $row['EndTime']
                    $Sheet1.cells.item($x, 3) = $row['CustomerAccountNumber']
                    $Sheet1.cells.item($x, 4) = $row['InitiatedByUser']
                    $Sheet1.cells.item($x, 5) = $row['RecoveryPlanName']
                    $Sheet1.cells.item($x, 6) = $row['RecoveryPlanNiceName']
                    $Sheet1.Cells.item($x, 7) = $row['HostingAccountNumber']
                    $Sheet1.cells.item($x, 8) = $row['CustomerAccountNumber']
                    $Sheet1.cells.item($x, 9) = $ChargeComponentId
                    $Sheet1.cells.item($x, 10) = $Device
                    $Sheet1.cells.item($x, 11) = $row['UserAction']
                    $Sheet1.cells.item($x, 12) = $VMInfo['NumberOfCores']
                    $Sheet1.cells.item($x, 13) = "Cloud - vCPUs" # include the number of cpus for this device
                    $x++
                    $Sheet1.cells.item($x, 1) = $row['StartTime']
                    $Sheet1.cells.item($x, 2) = $row['EndTime']
                    $Sheet1.cells.item($x, 3) = $row['CustomerAccountNumber']
                    $Sheet1.cells.item($x, 4) = $row['InitiatedByUser']
                    $Sheet1.cells.item($x, 5) = $row['RecoveryPlanName']
                    $Sheet1.cells.item($x, 6) = $row['RecoveryPlanNiceName']
                    $Sheet1.Cells.item($x, 7) = $row['HostingAccountNumber']
                    $Sheet1.cells.item($x, 8) = $row['CustomerAccountNumber']
                    $Sheet1.cells.item($x, 9) = $ChargeComponentId
                    $Sheet1.cells.item($x, 10) = $Device
                    $Sheet1.cells.item($x, 11) = $row['UserAction']
                    $Sheet1.cells.item($x, 12) = $VMInfo['SizeInMegabytes'] / 1024
                    $Sheet1.cells.item($x, 13) = "Cloud - RAM GB" # include the number of cpus for this device
                    $x++
                }
           }
        }
    }
    
    
    $Today = Get-Date -Format ddMMMyyyy
    $FilePath = $ExcelWorkbookPath + $Today + ".xlsx"
    if (test-path $FilePath) 
    {
        Remove-Item $FilePath
    }
    $Excel.ActiveWorkbook.SaveAs($FilePath)
    $Excel.quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel)
    
    return $DataSet.Tables[0]
}



Function SendMail()
{
    Start-Sleep -s 20
    $SmtpServer = ""

    $Message = New-Object System.Net.Mail.MailMessage
    $Smtp = New-Object Net.Mail.SmtpClient($SmtpServer)
    
    $Message.From = "me@me.com"
    
    $Message.To.Add("myemail")

    $yesterday = (Get-Date).AddMonths(-1).ToString("MMMMMM")
    $Message.Subject = "Billing Report for " + $yesterday
    $Date = Get-Date -Format ddMMMyyyy
    $FileAttachment = $ExcelWorkbookPath + $Date + ".xlsx"
    $Attachment = New-Object System.Net.Mail.Attachment($FileAttachment, 'text/plan')
    if ($Attachment)
    {
        $Message.Attachments.Add($Attachment)
    }
    $Smtp.Send($Message)
    $Attachment.Dispose()
    $Message.Dispose()
}

Function ArchiveReport()
{
    $Date = Get-Date -Format ddMMMyyyy
    Move-Item ($ExcelWorkbookPath + $Date + ".xlsx") $ExcelArchivePath
}

GetYesterdayRecoveryRuns
SendMail
ArchiveReport
