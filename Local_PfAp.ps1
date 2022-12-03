# Get the SuperFetch info from
# HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Superfetch\PfAp 
#
# Since Value namess might not be the same in different machine:
$key           = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Superfetch\PfAp"
$KeyValues     = Get-Item -Path $key -ErrorAction Stop 
$keyProperties = Get-ItemProperty -Path $key -ErrorAction Stop
$UserTimeValue = $KeyValues.Property.Where{$_.startswith('UserTime') }
$UserTime      = $keyProperties.$UserTimeValue
$FetchValue    = $KeyValues.Property.Where{$_.startswith('ApFetch') }
$Fetch         = $keyProperties.$FetchValue
$LaunchValue   = $KeyValues.Property.Where{$_.startswith('ApLaunch') }
$Launch        = $keyProperties.$LaunchValue
# - ApFetch_%SIDHashed Compressed buffer. (not seen anything of interest here yet)
# - ApLaunch_%SIDHashed Compressed buffer with a fixed size contains Win Universal Windows Platform (UWP) Apps. This buffer is updated periodically.
# - UserTime_%ID Compressed buffer related to the context for a given user. This buffer is updated periodically.
# More info at: https://papers.vx-underground.org/papers/Windows/Analysis%20and%20Internals/Superfetch%20-%20Unknown%20Spy.pdf
#
# XpressStream decompress C# code sourced from:
# https://github.com/EricZimmerman/Prefetch/blob/master/Prefetch/XpressStream/Xpress2.cs
$xpress = @"
using System;
using System.Runtime.InteropServices;

namespace Prefetch.XpressStream
{
    public class Xpress2
    {
        //  const ushort COMPRESSION_FORMAT_LZNT1 = 2;
        //  const ushort COMPRESSION_FORMAT_XPRESS = 3;
        private const ushort CompressionFormatXpressHuff = 4;

        [DllImport("ntdll.dll")]
        private static extern uint RtlGetCompressionWorkSpaceSize(ushort compressionFormat,
            ref ulong compressBufferWorkSpaceSize, ref ulong compressFragmentWorkSpaceSize);

        [DllImport("ntdll.dll")]
        private static extern uint RtlDecompressBufferEx(ushort compressionFormat, byte[] uncompressedBuffer,
            int uncompressedBufferSize, byte[] compressedBuffer, int compressedBufferSize, ref int finalUncompressedSize,
            byte[] workSpace);

        public static byte[] Decompress(byte[] buffer, ulong decompressedSize)
        {
            // our uncompressed data will go here
            var outBuf = new byte[decompressedSize];
            ulong compressBufferWorkSpaceSize = 0;
            ulong compressFragmentWorkSpaceSize = 0;

            //get the size of what our workspace needs to be
            var ret = RtlGetCompressionWorkSpaceSize(CompressionFormatXpressHuff, ref compressBufferWorkSpaceSize,
                ref compressFragmentWorkSpaceSize);
            if (ret != 0)
            {
                return null;
            }

            var workSpace = new byte[compressFragmentWorkSpaceSize];
            var dstSize = 0;

            ret = RtlDecompressBufferEx(CompressionFormatXpressHuff, outBuf, outBuf.Length, buffer, buffer.Length,
                ref dstSize, workSpace);
            //if (ret == 0)
            // {
                return outBuf;
            //   }

            //return null;
        }
    }
}
"@
$null = Add-Type -TypeDefinition $xpress
cls

# Function to Process the ApLaunch decompressed data from a Byte Array
function Get-DecompressedInfo{
param
	(
		[Parameter(Mandatory = $true)]
		[Byte[]]$decompressed
	)

    $dBversion = [System.BitConverter]::ToUint32($decompressed[0..3],0)
    $numberofentries = [System.BitConverter]::ToUint32($decompressed[4..7],0)

    Write-Host "------------------------------------"
    write-host "dB Version: $($dBversion)"
    write-host "Number of Entries: $($numberofentries)"
    Write-Host "(Header size: 8 - Entry length: 352)"
    Write-Host "------------------------------------"
    $start = 8
    $offset = $start

    $entries =  @(for($x = 0;$x -lt $numberofentries;$x++){
  
         $Application = [System.Text.Encoding]::Unicode.GetString($decompressed[($offset)..($offset+263)]).Replace(' ','')
         $tsd         = [System.BitConverter]::ToUint64($decompressed[($offset+264)..($offset+271)],0)
         $timestamp   = [datetime]::FromFileTimeUtc($tsd).ToString("dd/MM/yyyy HH:mm:ss.fffffff")
         $Hash        = [System.BitConverter]::ToString($decompressed[($offset+340)..($offset+340+3)]).Replace("-", "")
         $flag        = [System.BitConverter]::ToUint32($decompressed[($offset+344)..($offset+344+3)],0)

         [pscustomobject]@{
            'Offset'     = $offset.ToString('D6')
            'Application'= $Application
            'Timestamp'  = $timestamp
            'Hash'       = $Hash
            'Flag'       = [System.Boolean]$flag
            }
         $offset = $offset + 352
     })
     $entries
     $decompressed = $null

} # End Get-Launch

 
if($UserTime){

$value = [System.BitConverter]::ToString($UserTime[0..7]).Replace("-", "")
try{
    $tm0 = [System.BitConverter]::ToUint64($UserTime[8..15],0)
    $timestamp0 = [datetime]::FromFileTimeUtc($tm0).ToString("dd/MM/yyyy HH:mm:ss.fffffff")
}
catch{$timestamp0 = '--'}
try{
    $tm1 = [System.BitConverter]::ToUint64($UserTime[16..23],0)
    $timestamp1 = [datetime]::FromFileTimeUtc($tm1).ToString("dd/MM/yyyy HH:mm:ss.fffffff")
}
catch{$timestamp1 = '--'}

if($Fetch){

$FetchSize = $Fetch.Length

		# File Signature
		$FetchSignature = [System.BitConverter]::ToString($Fetch[0 .. 3]).Replace("-", "")
	    # Total uncompressed data size
		$FetchTotalUncompressedSize = [Bitconverter]::ToUInt32($Fetch[4 .. 7], 0)
        # Data
        $fetchuncompressed = if($FetchTotalUncompressedSize -ge 8){[Prefetch.XpressStream.Xpress2]::Decompress($Fetch[8..($FetchSize -8 -1)], $FetchTotalUncompressedSize) }
}

if(!!$Launch){
$LaunchSize = $Launch.Length

		# File Signature
		$LaunchSignature = [System.BitConverter]::ToString($Launch[0 .. 3]).Replace("-", "")
	    # Total uncompressed data size
		$LaunchTotalUncompressedSize = [Bitconverter]::ToUInt32($Launch[4 .. 7], 0)
        # Data
        $LCompressed = $Launch[12 .. (($Launch.Length) - 13)]
        $LaunchUncompressed = if($LaunchTotalUncompressedSize -ge 8){[Prefetch.XpressStream.Xpress2]::Decompress($LCompressed,$LaunchTotalUncompressedSize) }
        $LaunchedApps =   try{ Get-DecompressedInfo -decompressed $Launchuncompressed } 
                        catch{ $null}
        
        # Export uncompressed Fetch data
        $exportedfile = "$($env:TEMP)\decompressed_$($LaunchValue).hex"
        $OutputFileStream = [IO.File]::OpenWrite($exportedfile)
        $OutputFileStream.Write($LaunchUncompressed, 0, $LaunchTotalUncompressedSize)
        $OutputFileStream.Dispose()
        Write-Host "The decompressed contents of $($LaunchValue) are saved to $($exportedfile)" -f White
}


    [pscustomobject]@{
        "$($UserTimeValue) Value"                 = $value
        "$($UserTimeValue) TimeStamp 1"           = $timestamp0
        "$($UserTimeValue) TimeStamp 2"           = $timestamp1
        "$($FetchValue) Signature"                = $FetchSignature
        "$($FetchValue) Total Compressed Size"    = $FetchSize
        "$($FetchValue) Total Uncompressed Size"  = $FetchTotalUncompressedSize
        "$($FetchValue) Data"                     = $fetchuncompressedhex
        "$($LaunchValue) Signature"               = $LaunchSignature
        "$($LaunchValue) Total Compressed Size"   = $LaunchSize
        "$($LaunchValue) Total Uncompressed Size" = $LaunchTotalUncompressedSize
    }

    $LaunchedApps|Out-GridView -PassThru

} #endif keys