$ShrinkSizeGB = 10
$DriveLetterToCreate = "D"
$FileSystemLabel = "Data"

# Check whether the D: drive already exists
if (Get-Volume -DriveLetter $DriveLetterToCreate -ErrorAction SilentlyContinue) {
    Write-Error "$DriveLetterToCreate`: drive already exists. Aborting."
    exit 1
}

# Get the C: partition
$CPartition = Get-Partition -DriveLetter C
if (-not $CPartition) {
    Write-Error "Could not find the C: partition."
    exit 1
}

# Check the supported shrink size
$SupportedSize = Get-PartitionSupportedSize -DriveLetter C
$ShrinkSizeBytes = $ShrinkSizeGB * 1GB
$NewCSize = $CPartition.Size - $ShrinkSizeBytes

if ($NewCSize -lt $SupportedSize.SizeMin) {
    Write-Error "The C: drive cannot be shrunk by ${ShrinkSizeGB}GB."
    Write-Host "Current C: size: $([math]::Round($CPartition.Size / 1GB, 2)) GB"
    Write-Host "Minimum supported C: size: $([math]::Round($SupportedSize.SizeMin / 1GB, 2)) GB"
    exit 1
}

Write-Host "Shrinking the C: drive by ${ShrinkSizeGB}GB..."

# Shrink the C: drive
Resize-Partition -DriveLetter C -Size $NewCSize

Write-Host "Shrink completed. Creating the new partition..."

# Create a new partition on the same disk as C:
$DiskNumber = $CPartition.DiskNumber

$NewPartition = New-Partition `
    -DiskNumber $DiskNumber `
    -UseMaximumSize `
    -DriveLetter $DriveLetterToCreate

# Format the new partition as NTFS
Format-Volume `
    -Partition $NewPartition `
    -FileSystem NTFS `
    -NewFileSystemLabel $FileSystemLabel `
    -Confirm:$false

Write-Host "Completed successfully."
Write-Host "$DriveLetterToCreate`: drive has been created."