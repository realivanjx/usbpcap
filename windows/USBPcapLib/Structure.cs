using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace USBPcapLib
{
    internal class SafeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ConnectNamedPipe(IntPtr hNamedPipe, [In] ref System.Threading.NativeOverlapped lpOverlapped);

        [DllImport("kernel32.dll")]
        internal static extern FileType GetFileType(IntPtr hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, out uint lpNumberOfBytesRead, ref System.Threading.NativeOverlapped lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetOverlappedResult(IntPtr hFile, [In] ref System.Threading.NativeOverlapped lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait);

        [DllImport("ntdll.dll")]
        internal static extern int NtQueryDirectoryObject(IntPtr DirectoryHandle, IntPtr Buffer, int Length,
            bool ReturnSingleEntry, bool RestartScan, ref uint Context, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        internal static extern int NtOpenDirectoryObject(out IntPtr DirectoryHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        internal static extern int NtClose(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = false)]
        internal static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetProcessHeap();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CreateFile(
             [MarshalAs(UnmanagedType.LPTStr)] string filename,
             [MarshalAs(UnmanagedType.U4)] FileAccess access,
             [MarshalAs(UnmanagedType.U4)] FileShare share,
             IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
             [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
             [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
             IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern CONFIGRET CM_Locate_DevNodeA(ref uint pdnDevInst, string pDeviceID, int ulFlags);

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern CONFIGRET CM_Get_DevNode_Registry_Property(
              uint deviceInstance,
              uint property,
              out Microsoft.Win32.RegistryValueKind pulRegDataType,
              IntPtr buffer,
              ref uint length,
              uint flags);

        [DllImport("setupapi.dll")]
        internal static extern CONFIGRET CM_Get_Parent(out uint pdnDevInst, uint dnDevInst, int ulFlags);

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern CONFIGRET CM_Get_Child(ref uint pdnDevInst, uint dnDevInst, int ulFlags);

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern CONFIGRET CM_Get_Sibling(ref uint pdnDevInst, uint DevInst, int ulFlags);

        internal static int CTL_CODE(int deviceType, int function, int method, int access)
        {
            return (deviceType << 16) | (access << 14) | (function << 2) | method;
        }

        internal static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        internal static uint LOOP_SANITY_LIMIT = 10000;
        internal static uint MAX_DEVICE_ID_LEN = 200;
        internal static uint DEFAULT_SNAPSHOT_LENGTH = 65535 * 100;
        internal static uint DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE = 1024 * 1024 * 100;

        internal static int ERROR_IO_PENDING = 997;
        internal static int ERROR_PIPE_CONNECTED = 535;

        internal static uint IOCTL_USBPCAP_SETUP_BUFFER
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_UNKNOWN, 0x800,
                    (int)IOCTL_METHOD.METHOD_BUFFERED, (int)IOCTL_FILE_ACCESS.FILE_READ_ACCESS);
            }
        }

        internal static uint IOCTL_USBPCAP_START_FILTERING
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_UNKNOWN, 0x801, (int)IOCTL_METHOD.METHOD_BUFFERED,
                    (int)(IOCTL_FILE_ACCESS.FILE_READ_ACCESS | IOCTL_FILE_ACCESS.FILE_WRITE_ACCESS));
            }
        }

        internal static uint IOCTL_USBPCAP_STOP_FILTERING
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_UNKNOWN, 0x802, (int)IOCTL_METHOD.METHOD_BUFFERED,
                    (int)(IOCTL_FILE_ACCESS.FILE_READ_ACCESS | IOCTL_FILE_ACCESS.FILE_WRITE_ACCESS));
            }
        }

        internal static uint IOCTL_USBPCAP_GET_HUB_SYMLINK
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_UNKNOWN, 0x803, (int)IOCTL_METHOD.METHOD_BUFFERED,
                    (int)IOCTL_FILE_ACCESS.FILE_ANY_ACCESS);
            }
        }

        internal static uint IOCTL_USBPCAP_SET_SNAPLEN_SIZE
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_UNKNOWN, 0x804,
                    (int)IOCTL_METHOD.METHOD_BUFFERED, (int)IOCTL_FILE_ACCESS.FILE_READ_ACCESS);
            }
        }

        public const uint USB_GET_NODE_INFORMATION = 258;
        public const uint USB_GET_NODE_CONNECTION_INFORMATION = 259;
        public const uint USB_GET_NODE_CONNECTION_NAME = 261;
        public const uint USB_GET_NODE_CONNECTION_DRIVERKEY_NAME = 264;

        internal static uint IOCTL_USB_GET_NODE_INFORMATION
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_USB, (int)USB_GET_NODE_INFORMATION,
                    (int)IOCTL_METHOD.METHOD_BUFFERED, (int)IOCTL_FILE_ACCESS.FILE_ANY_ACCESS);
            }
        }

        internal static uint IOCTL_USB_GET_NODE_CONNECTION_INFORMATION
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_USB, (int)USB_GET_NODE_CONNECTION_INFORMATION,
                    (int)IOCTL_METHOD.METHOD_BUFFERED, (int)IOCTL_FILE_ACCESS.FILE_ANY_ACCESS);
            }
        }

        internal static uint IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_USB, (int)USB_GET_NODE_CONNECTION_DRIVERKEY_NAME,
                    (int)IOCTL_METHOD.METHOD_BUFFERED, (int)IOCTL_FILE_ACCESS.FILE_ANY_ACCESS);
            }
        }

        internal static uint IOCTL_USB_GET_NODE_CONNECTION_NAME
        {
            get
            {
                return (uint)CTL_CODE((int)IOCTL_FILE_DEVICE.FILE_DEVICE_USB, (int)USB_GET_NODE_CONNECTION_NAME,
                    (int)IOCTL_METHOD.METHOD_BUFFERED, (int)IOCTL_FILE_ACCESS.FILE_ANY_ACCESS);
            }
        }

    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct USB_NODE_CONNECTION_DRIVERKEY_NAME
    {
        public uint ConnectionIndex;  /* INPUT */
        public uint ActualLength;     /* OUTPUT */
        /* unicode name for the devnode */
        public fixed char DriverKeyName[1]; /* OUTPUT */
    }

    public enum IOCTL_FILE_DEVICE
    {
        FILE_DEVICE_UNKNOWN = 0x00000022,
        FILE_DEVICE_USB = 0x00000022,
    }

    public enum IOCTL_METHOD
    {
        METHOD_BUFFERED = 0,
        METHOD_IN_DIRECT = 1,
        METHOD_OUT_DIRECT = 2,
        METHOD_NEITHER = 3,
    }

    public enum IOCTL_FILE_ACCESS
    {
        FILE_ANY_ACCESS = 0,
        FILE_SPECIAL_ACCESS = FILE_ANY_ACCESS,
        FILE_READ_ACCESS = 0x0001,
        FILE_WRITE_ACCESS = 0x0002,
    }

    public enum DIRECTORY_ACCESS
    {
        DIRECTORY_QUERY = 0x0001,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct OBJDIR_INFORMATION
    {
        public UNICODE_STRING ObjectName;
        public UNICODE_STRING ObjectTypeName;
        public fixed byte Data[1];
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

        public OBJECT_ATTRIBUTES(string name, uint attrs)
        {
            Length = 0;
            RootDirectory = IntPtr.Zero;
            objectName = IntPtr.Zero;
            Attributes = attrs;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;

            Length = Marshal.SizeOf(this);
            ObjectName = new UNICODE_STRING(name);
        }

        public UNICODE_STRING ObjectName
        {
            get
            {
                return (UNICODE_STRING)Marshal.PtrToStructure(objectName, typeof(UNICODE_STRING));
            }

            set
            {
                bool fDeleteOld = objectName != IntPtr.Zero;
                if (!fDeleteOld)
                    objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                Marshal.StructureToPtr(value, objectName, fDeleteOld);
            }
        }

        public void Dispose()
        {
            if (objectName != IntPtr.Zero)
            {
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
        }
    }

    [Flags]
    public enum FileAccess : uint
    {
        None = 0,
        //
        // Standart Section
        //

        AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
        MaximumAllowed = 0x2000000,     // MaximumAllowed access type

        Delete = 0x10000,
        ReadControl = 0x20000,
        WriteDAC = 0x40000,
        WriteOwner = 0x80000,
        Synchronize = 0x100000,

        StandardRightsRequired = 0xF0000,
        StandardRightsRead = ReadControl,
        StandardRightsWrite = ReadControl,
        StandardRightsExecute = ReadControl,
        StandardRightsAll = 0x1F0000,
        SpecificRightsAll = 0xFFFF,

        FILE_READ_DATA = 0x0001,        // file & pipe
        FILE_LIST_DIRECTORY = 0x0001,       // directory
        FILE_WRITE_DATA = 0x0002,       // file & pipe
        FILE_ADD_FILE = 0x0002,         // directory
        FILE_APPEND_DATA = 0x0004,      // file
        FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
        FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
        FILE_READ_EA = 0x0008,          // file & directory
        FILE_WRITE_EA = 0x0010,         // file & directory
        FILE_EXECUTE = 0x0020,          // file
        FILE_TRAVERSE = 0x0020,         // directory
        FILE_DELETE_CHILD = 0x0040,     // directory
        FILE_READ_ATTRIBUTES = 0x0080,      // all
        FILE_WRITE_ATTRIBUTES = 0x0100,     // all

        //
        // Generic Section
        //

        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000,

        SPECIFIC_RIGHTS_ALL = 0x00FFFF,
        FILE_ALL_ACCESS =
        StandardRightsRequired |
        Synchronize |
        0x1FF,

        FILE_GENERIC_READ =
        StandardRightsRead |
        FILE_READ_DATA |
        FILE_READ_ATTRIBUTES |
        FILE_READ_EA |
        Synchronize,

        FILE_GENERIC_WRITE =
        StandardRightsWrite |
        FILE_WRITE_DATA |
        FILE_WRITE_ATTRIBUTES |
        FILE_WRITE_EA |
        FILE_APPEND_DATA |
        Synchronize,

        FILE_GENERIC_EXECUTE =
        StandardRightsExecute |
          FILE_READ_ATTRIBUTES |
          FILE_EXECUTE |
          Synchronize
    }

    [Flags]
    public enum FileShare : uint
    {
        /// <summary>
        ///
        /// </summary>
        None = 0x00000000,
        /// <summary>
        /// Enables subsequent open operations on an object to request read access.
        /// Otherwise, other processes cannot open the object if they request read access.
        /// If this flag is not specified, but the object has been opened for read access, the function fails.
        /// </summary>
        Read = 0x00000001,
        /// <summary>
        /// Enables subsequent open operations on an object to request write access.
        /// Otherwise, other processes cannot open the object if they request write access.
        /// If this flag is not specified, but the object has been opened for write access, the function fails.
        /// </summary>
        Write = 0x00000002,
        /// <summary>
        /// Enables subsequent open operations on an object to request delete access.
        /// Otherwise, other processes cannot open the object if they request delete access.
        /// If this flag is not specified, but the object has been opened for delete access, the function fails.
        /// </summary>
        Delete = 0x00000004
    }

    public enum CreationDisposition : uint
    {
        /// <summary>
        /// Creates a new file. The function fails if a specified file exists.
        /// </summary>
        New = 1,
        /// <summary>
        /// Creates a new file, always.
        /// If a file exists, the function overwrites the file, clears the existing attributes, combines the specified file attributes,
        /// and flags with FILE_ATTRIBUTE_ARCHIVE, but does not set the security descriptor that the SECURITY_ATTRIBUTES structure specifies.
        /// </summary>
        CreateAlways = 2,
        /// <summary>
        /// Opens a file. The function fails if the file does not exist.
        /// </summary>
        OpenExisting = 3,
        /// <summary>
        /// Opens a file, always.
        /// If a file does not exist, the function creates a file as if dwCreationDisposition is CREATE_NEW.
        /// </summary>
        OpenAlways = 4,
        /// <summary>
        /// Opens a file and truncates it so that its size is 0 (zero) bytes. The function fails if the file does not exist.
        /// The calling process must open the file with the GENERIC_WRITE access right.
        /// </summary>
        TruncateExisting = 5
    }

    [Flags]
    public enum FileAttributes : uint
    {
        None = 0,
        Readonly = 0x00000001,
        Hidden = 0x00000002,
        System = 0x00000004,
        Directory = 0x00000010,
        Archive = 0x00000020,
        Device = 0x00000040,
        Normal = 0x00000080,
        Temporary = 0x00000100,
        SparseFile = 0x00000200,
        ReparsePoint = 0x00000400,
        Compressed = 0x00000800,
        Offline = 0x00001000,
        NotContentIndexed = 0x00002000,
        Encrypted = 0x00004000,
        Write_Through = 0x80000000,
        Overlapped = 0x40000000,
        NoBuffering = 0x20000000,
        RandomAccess = 0x10000000,
        SequentialScan = 0x08000000,
        DeleteOnClose = 0x04000000,
        BackupSemantics = 0x02000000,
        PosixSemantics = 0x01000000,
        OpenReparsePoint = 0x00200000,
        OpenNoRecall = 0x00100000,
        FirstPipeInstance = 0x00080000
    }

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct USB_NODE_INFORMATION
    {
        [FieldOffset(0)]
        public USB_HUB_NODE NodeType;        /* hub, mi parent */

        [FieldOffset(4)]
        public USB_HUB_INFORMATION HubInformation;

        [FieldOffset(4)]
        public USB_MI_PARENT_INFORMATION MiParentInformation;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USB_MI_PARENT_INFORMATION
    {
        public uint NumberOfInterfaces;
    }

    public enum USB_HUB_NODE
    {
        UsbHub,
        UsbMIParent
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USB_HUB_INFORMATION
    {
        /*
           copy of data from hub descriptor
        */
        public USB_HUB_DESCRIPTOR HubDescriptor;
        public bool HubIsBusPowered;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct USB_HUB_DESCRIPTOR
    {
        public byte bDescriptorLength;
        public byte bDescriptorType;
        public byte bNumberOfPorts;
        public ushort wHubCharacteristics;
        public byte bPowerOnToPowerGood;
        public byte bHubControlCurrent;
        public fixed byte bRemoveAndPowerMask[64];
    }

    /** IOCTL_USB_GET_NODE_CONNECTION_NAME **/
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct USB_NODE_CONNECTION_NAME
    {
        public uint ConnectionIndex;  /* INPUT */
        public uint ActualLength;     /* OUTPUT */
        /* unicode symbolic name for this node if it is a hub or parent driver
           null if this node is a device. */
        public fixed char NodeName[1];      /* OUTPUT */
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USB_NODE_CONNECTION_INFORMATION
    {
        public uint ConnectionIndex;  /* INPUT */
        /* usb device descriptor returned by this device
           during enumeration */
        public USB_DEVICE_DESCRIPTOR DeviceDescriptor; /* OUTPUT */
        public byte CurrentConfigurationValue;/* OUTPUT */
        public bool LowSpeed;/* OUTPUT */
        public bool DeviceIsHub;/* OUTPUT */
        public ushort DeviceAddress;/* OUTPUT */
        public uint NumberOfOpenPipes;/* OUTPUT */
        public USB_CONNECTION_STATUS ConnectionStatus;/* OUTPUT */
        /* public USB_PIPE_INFO PipeList[0]; */ /* OUTPUT */
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USB_DEVICE_DESCRIPTOR
    {
        public byte bLength;
        public byte bDescriptorType;
        public ushort bcdUSB;
        public byte bDeviceClass;
        public byte bDeviceSubClass;
        public byte bDeviceProtocol;
        public byte bMaxPacketSize0;
        public ushort idVendor;
        public ushort idProduct;
        public ushort bcdDevice;
        public byte iManufacturer;
        public byte iProduct;
        public byte iSerialNumber;
        public byte bNumConfigurations;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USB_ENDPOINT_DESCRIPTOR
    {
        public byte bLength;
        public byte bDescriptorType;
        public byte bEndpointAddress;
        public byte bmAttributes;
        public ushort wMaxPacketSize;
        public byte bInterval;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USB_PIPE_INFO
    {
        public USB_ENDPOINT_DESCRIPTOR EndpointDescriptor;
        public uint ScheduleOffset;
    }

    /* USBPCAP_ADDRESS_FILTER is parameter structure to IOCTL_USBPCAP_START_FILTERING. */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct USBPCAP_ADDRESS_FILTER
    {
        /* Individual device filter bit array. USB standard assigns device
         * numbers 1 to 127 (0 is reserved for initial configuration).
         *
         * If address 0 bit is set, then we will automatically capture from
         * newly connected devices.
         *
         * addresses[0] - 0 - 31
         * addresses[1] - 32 - 63
         * addresses[2] - 64 - 95
         * addresses[3] - 96 - 127
         */
        public fixed uint addresses[4];

        /* Filter all devices */
        public bool filterAll;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct USBPCAP_IOCTL_SIZE
    {
        public uint size;
    }

    public enum USB_CONNECTION_STATUS
    {
        NoDeviceConnected,
        DeviceConnected,

        /* failure codes, these map to fail reasons */
        DeviceFailedEnumeration,
        DeviceGeneralFailure,
        DeviceCausedOvercurrent,
        DeviceNotEnoughPower,
        DeviceNotEnoughBandwidth,
        DeviceHubNestedTooDeeply,
        DeviceInLegacyHub,
        DeviceEnumerating,
        DeviceReset
    }

    public enum CM_DRP
    {
        CM_DRP_DEVICEDESC = (0x00000001), // DeviceDesc REG_SZ property (RW)
        CM_DRP_HARDWAREID = (0x00000002), // HardwareID REG_MULTI_SZ property (RW)
        CM_DRP_COMPATIBLEIDS = (0x00000003), // CompatibleIDs REG_MULTI_SZ property (RW)
        CM_DRP_UNUSED0 = (0x00000004), // unused
        CM_DRP_SERVICE = (0x00000005), // Service REG_SZ property (RW)
        CM_DRP_UNUSED1 = (0x00000006), // unused
        CM_DRP_UNUSED2 = (0x00000007), // unused
        CM_DRP_CLASS = (0x00000008), // Class REG_SZ property (RW)
        CM_DRP_CLASSGUID = (0x00000009), // ClassGUID REG_SZ property (RW)
        CM_DRP_DRIVER = (0x0000000A), // Driver REG_SZ property (RW)
        CM_DRP_CONFIGFLAGS = (0x0000000B), // ConfigFlags REG_DWORD property (RW)
        CM_DRP_MFG = (0x0000000C), // Mfg REG_SZ property (RW)
        CM_DRP_FRIENDLYNAME = (0x0000000D), // FriendlyName REG_SZ property (RW)
        CM_DRP_LOCATION_INFORMATION = (0x0000000E), // LocationInformation REG_SZ property (RW)
        CM_DRP_PHYSICAL_DEVICE_OBJECT_NAME = (0x0000000F), // PhysicalDeviceObjectName REG_SZ property (R)
        CM_DRP_CAPABILITIES = (0x00000010), // Capabilities REG_DWORD property (R)
        CM_DRP_UI_NUMBER = (0x00000011), // UiNumber REG_DWORD property (R)
        CM_DRP_UPPERFILTERS = (0x00000012), // UpperFilters REG_MULTI_SZ property (RW)
    }

    public enum CONFIGRET
    {
        CR_SUCCESS = (0x00000000),
        CR_DEFAULT = (0x00000001),
        CR_OUT_OF_MEMORY = (0x00000002),
        CR_INVALID_POINTER = (0x00000003),
        CR_INVALID_FLAG = (0x00000004),
        CR_INVALID_DEVNODE = (0x00000005),
        CR_INVALID_DEVINST = CR_INVALID_DEVNODE,
        CR_INVALID_RES_DES = (0x00000006),
        CR_INVALID_LOG_CONF = (0x00000007),
        CR_INVALID_ARBITRATOR = (0x00000008),
        CR_INVALID_NODELIST = (0x00000009),
        CR_DEVNODE_HAS_REQS = (0x0000000A),
        CR_DEVINST_HAS_REQS = CR_DEVNODE_HAS_REQS,
        CR_INVALID_RESOURCEID = (0x0000000B),
        CR_DLVXD_NOT_FOUND = (0x0000000C),   // WIN 95 ONLY
        CR_NO_SUCH_DEVNODE = (0x0000000D),
        CR_NO_SUCH_DEVINST = CR_NO_SUCH_DEVNODE,
        CR_NO_MORE_LOG_CONF = (0x0000000E),
        CR_NO_MORE_RES_DES = (0x0000000F),
        CR_ALREADY_SUCH_DEVNODE = (0x00000010),
        CR_ALREADY_SUCH_DEVINST = CR_ALREADY_SUCH_DEVNODE,
        CR_INVALID_RANGE_LIST = (0x00000011),
        CR_INVALID_RANGE = (0x00000012),
        CR_FAILURE = (0x00000013),
        CR_NO_SUCH_LOGICAL_DEV = (0x00000014),
        CR_CREATE_BLOCKED = (0x00000015),
        CR_NOT_SYSTEM_VM = (0x00000016),   // WIN 95 ONLY
        CR_REMOVE_VETOED = (0x00000017),
        CR_APM_VETOED = (0x00000018),
        CR_INVALID_LOAD_TYPE = (0x00000019),
        CR_BUFFER_SMALL = (0x0000001A),
        CR_NO_ARBITRATOR = (0x0000001B),
        CR_NO_REGISTRY_HANDLE = (0x0000001C),
        CR_REGISTRY_ERROR = (0x0000001D),
        CR_INVALID_DEVICE_ID = (0x0000001E),
        CR_INVALID_DATA = (0x0000001F),
        CR_INVALID_API = (0x00000020),
        CR_DEVLOADER_NOT_READY = (0x00000021),
        CR_NEED_RESTART = (0x00000022),
        CR_NO_MORE_HW_PROFILES = (0x00000023),
        CR_DEVICE_NOT_THERE = (0x00000024),
        CR_NO_SUCH_VALUE = (0x00000025),
        CR_WRONG_TYPE = (0x00000026),
        CR_INVALID_PRIORITY = (0x00000027),
        CR_NOT_DISABLEABLE = (0x00000028),
        CR_FREE_RESOURCES = (0x00000029),
        CR_QUERY_VETOED = (0x0000002A),
        CR_CANT_SHARE_IRQ = (0x0000002B),
        CR_NO_DEPENDENT = (0x0000002C),
        CR_SAME_RESOURCES = (0x0000002D),
        CR_NO_SUCH_REGISTRY_KEY = (0x0000002E),
        CR_INVALID_MACHINENAME = (0x0000002F),   // NT ONLY
        CR_REMOTE_COMM_FAILURE = (0x00000030),   // NT ONLY
        CR_MACHINE_UNAVAILABLE = (0x00000031),   // NT ONLY
        CR_NO_CM_SERVICES = (0x00000032),   // NT ONLY
        CR_ACCESS_DENIED = (0x00000033),   // NT ONLY
        CR_CALL_NOT_IMPLEMENTED = (0x00000034),
        CR_INVALID_PROPERTY = (0x00000035),
        CR_DEVICE_INTERFACE_ACTIVE = (0x00000036),
        CR_NO_SUCH_DEVICE_INTERFACE = (0x00000037),
        CR_INVALID_REFERENCE_STRING = (0x00000038),
        CR_INVALID_CONFLICT_LIST = (0x00000039),
        CR_INVALID_INDEX = (0x0000003A),
        CR_INVALID_STRUCTURE_SIZE = (0x0000003B),
        NUM_CR_RESULTS = (0x0000003C),
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct pcap_hdr_t
    {
        public uint magic_number;   /* magic number */
        public ushort version_major;  /* major version number */
        public ushort version_minor;  /* minor version number */
        public int thiszone;       /* GMT to local correction */
        public uint sigfigs;        /* accuracy of timestamps */
        public uint snaplen;        /* max length of captured packets, in octets */
        public uint network;        /* data link type */
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct pcaprec_hdr_t
    {
        public uint ts_sec;         /* timestamp seconds */
        public uint ts_usec;        /* timestamp microseconds */
        public uint incl_len;       /* number of octets of packet saved in file */
        public uint orig_len;       /* actual length of packet */
    }

    public enum USBPCAP_TRANSFER_TYPE : byte
    {
        ISOCHRONOUS = 0,
        INTERRUPT = 1,
        CONTROL = 2,
        BULK = 3,
        IRP_INFO = 0xFE,
        UNKNOWN = 0xFF,
    }

    // https://desowin.org/usbpcap/captureformat.html
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct USBPCAP_BUFFER_PACKET_HEADER
    {
        public ushort headerLen; /* This header length */
        public ulong irpId;     /* I/O Request packet ID */
        public USBD_STATUS status;    /* USB status code
                                   (on return from host controller) */
        public URB_FUNCTION function;  /* URB Function */
        public byte info;      /* I/O Request info */

        public ushort bus;       /* bus (RootHub) number */
        public ushort device;    /* device address */
        public byte endpoint;  /* endpoint number and transfer direction */
        public USBPCAP_TRANSFER_TYPE transfer;  /* transfer type */

        public uint dataLength;/* Data length */

        public int EndpointNumber
        {
            get
            {
                return (endpoint & 0x0F);
            }
        }

        public bool In
        {
            get
            {
                return (endpoint & 0x80) == 0x80;
            }
        }

        public IRPDierction IrpDirection
        {
            get
            {
                if ((this.info & 0x01) == 0x0)
                {
                    return IRPDierction.FDO_TO_PDO;
                }
                else
                {
                    return IRPDierction.PDO_TO_FDO;
                }
            }
        }
    }

    public enum IRPDierction
    {
        FDO_TO_PDO = 0,
        PDO_TO_FDO = 1,
    }

    // https://github.com/tpn/winsdk-10/blob/master/Include/10.0.14393.0/shared/usb.h
    public enum URB_FUNCTION : ushort
    {
        URB_FUNCTION_SELECT_CONFIGURATION = 0x0000,
        URB_FUNCTION_SELECT_INTERFACE = 0x0001,
        URB_FUNCTION_ABORT_PIPE = 0x0002,
        URB_FUNCTION_TAKE_FRAME_LENGTH_CONTROL = 0x0003,
        URB_FUNCTION_RELEASE_FRAME_LENGTH_CONTROL = 0x0004,
        URB_FUNCTION_GET_FRAME_LENGTH = 0x0005,
        URB_FUNCTION_SET_FRAME_LENGTH = 0x0006,
        URB_FUNCTION_GET_CURRENT_FRAME_NUMBER = 0x0007,
        URB_FUNCTION_CONTROL_TRANSFER = 0x0008,
        URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER = 0x0009,
        URB_FUNCTION_ISOCH_TRANSFER = 0x000A,
        URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE = 0x000B,
        URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE = 0x000C,
        URB_FUNCTION_SET_FEATURE_TO_DEVICE = 0x000D,
        URB_FUNCTION_SET_FEATURE_TO_INTERFACE = 0x000E,
        URB_FUNCTION_SET_FEATURE_TO_ENDPOINT = 0x000F,
        URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE = 0x0010,
        URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE = 0x0011,
        URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT = 0x0012,
        URB_FUNCTION_GET_STATUS_FROM_DEVICE = 0x0013,
        URB_FUNCTION_GET_STATUS_FROM_INTERFACE = 0x0014,
        URB_FUNCTION_GET_STATUS_FROM_ENDPOINT = 0x0015,
        URB_FUNCTION_RESERVED_0X0016 = 0x0016,
        URB_FUNCTION_VENDOR_DEVICE = 0x0017,
        URB_FUNCTION_VENDOR_INTERFACE = 0x0018,
        URB_FUNCTION_VENDOR_ENDPOINT = 0x0019,
        URB_FUNCTION_CLASS_DEVICE = 0x001A,
        URB_FUNCTION_CLASS_INTERFACE = 0x001B,
        URB_FUNCTION_CLASS_ENDPOINT = 0x001C,
        URB_FUNCTION_RESERVE_0X001D = 0x001D,         // previously URB_FUNCTION_RESET_PIPE
        URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL = 0x001E,
        URB_FUNCTION_CLASS_OTHER = 0x001F,
        URB_FUNCTION_VENDOR_OTHER = 0x0020,
        URB_FUNCTION_GET_STATUS_FROM_OTHER = 0x0021,
        URB_FUNCTION_CLEAR_FEATURE_TO_OTHER = 0x0022,
        URB_FUNCTION_SET_FEATURE_TO_OTHER = 0x0023,
        URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT = 0x0024,
        URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT = 0x0025,
        URB_FUNCTION_GET_CONFIGURATION = 0x0026,
        URB_FUNCTION_GET_INTERFACE = 0x0027,
        URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE = 0x0028,
        URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE = 0x0029,

        URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR = 0x002A,
        URB_FUNCTION_SYNC_RESET_PIPE = 0x0030,
        URB_FUNCTION_SYNC_CLEAR_STALL = 0x0031,
        URB_FUNCTION_CONTROL_TRANSFER_EX = 0x0032,
        URB_FUNCTION_RESERVE_0X0033 = 0x0033,
        URB_FUNCTION_RESERVE_0X0034 = 0x0034,
        URB_FUNCTION_OPEN_STATIC_STREAMS = 0x0035,
        URB_FUNCTION_CLOSE_STATIC_STREAMS = 0x0036,
        URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER_USING_CHAINED_MDL = 0x0037,
        URB_FUNCTION_ISOCH_TRANSFER_USING_CHAINED_MDL = 0x0038,
        URB_FUNCTION_RESERVE_0X002B = 0x002B,
        URB_FUNCTION_RESERVE_0X002C = 0x002C,
        URB_FUNCTION_RESERVE_0X002D = 0x002D,
        URB_FUNCTION_RESERVE_0X002E = 0x002E,
        URB_FUNCTION_RESERVE_0X002F = 0x002F,
    }

    public enum USBD_STATUS : uint
    {
        USBD_STATUS_SUCCESS = 0x00000000,
        USBD_STATUS_PORT_OPERATION_PENDING = 0x00000001,
        USBD_STATUS_PENDING = 0x40000000,

        USBD_STATUS_CRC = 0xC0000001,
        USBD_STATUS_BTSTUFF = 0xC0000002,
        USBD_STATUS_DATA_TOGGLE_MISMATCH = 0xC0000003,
        USBD_STATUS_STALL_PID = 0xC0000004,
        USBD_STATUS_DEV_NOT_RESPONDING = 0xC0000005,
        USBD_STATUS_PID_CHECK_FAILURE = 0xC0000006,
        USBD_STATUS_UNEXPECTED_PID = 0xC0000007,
        USBD_STATUS_DATA_OVERRUN = 0xC0000008,
        USBD_STATUS_DATA_UNDERRUN = 0xC0000009,
        USBD_STATUS_RESERVED1 = 0xC000000A,
        USBD_STATUS_RESERVED2 = 0xC000000B,
        USBD_STATUS_BUFFER_OVERRUN = 0xC000000C,
        USBD_STATUS_BUFFER_UNDERRUN = 0xC000000D,
        USBD_STATUS_NOT_ACCESSED = 0xC000000F,
        USBD_STATUS_FIFO = 0xC0000010,
        USBD_STATUS_XACT_ERROR = 0xC0000011,
        USBD_STATUS_BABBLE_DETECTED = 0xC0000012,
        USBD_STATUS_DATA_BUFFER_ERROR = 0xC0000013,
        USBD_STATUS_NO_PING_RESPONSE = 0xC0000014,
        USBD_STATUS_INVALID_STREAM_TYPE = 0xC0000015,
        USBD_STATUS_INVALID_STREAM_ID = 0xC0000016,
        USBD_STATUS_ENDPOINT_HALTED = 0xC0000030,

        USBD_STATUS_INVALID_URB_FUNCTION = 0x80000200,
        USBD_STATUS_INVALID_PARAMETER = 0x80000300,
        USBD_STATUS_ERROR_BUSY = 0x80000400,
        USBD_STATUS_INVALID_PIPE_HANDLE = 0x80000600,
        USBD_STATUS_NO_BANDWIDTH = 0x80000700,
        USBD_STATUS_INTERNAL_HC_ERROR = 0x80000800,
        USBD_STATUS_ERROR_SHORT_TRANSFER = 0x80000900,
        USBD_STATUS_BAD_START_FRAME = 0xC0000A00,
        USBD_STATUS_ISOCH_REQUEST_FAILED = 0xC0000B00,
        USBD_STATUS_FRAME_CONTROL_OWNED = 0xC0000C00,
        USBD_STATUS_FRAME_CONTROL_NOT_OWNED = 0xC0000D00,
        USBD_STATUS_NOT_SUPPORTED = 0xC0000E00,
        USBD_STATUS_INVALID_CONFIGURATION_DESCRIPTOR = 0xC0000F00,
        USBD_STATUS_INSUFFICIENT_RESOURCES = 0xC0001000,
        USBD_STATUS_SET_CONFIG_FAILED = 0xC0002000,
        USBD_STATUS_BUFFER_TOO_SMALL = 0xC0003000,
        USBD_STATUS_INTERFACE_NOT_FOUND = 0xC0004000,
        USBD_STATUS_INAVLID_PIPE_FLAGS = 0xC0005000,
        USBD_STATUS_TIMEOUT = 0xC0006000,
        USBD_STATUS_DEVICE_GONE = 0xC0007000,
        USBD_STATUS_STATUS_NOT_MAPPED = 0xC0008000,
        USBD_STATUS_HUB_INTERNAL_ERROR = 0xC0009000,
        USBD_STATUS_CANCELED = 0xC0010000,
        USBD_STATUS_ISO_NOT_ACCESSED_BY_HW = 0xC0020000,
        USBD_STATUS_ISO_TD_ERROR = 0xC0030000,
        USBD_STATUS_ISO_NA_LATE_USBPORT = 0xC0040000,
        USBD_STATUS_ISO_NOT_ACCESSED_LATE = 0xC0050000,
        USBD_STATUS_BAD_DESCRIPTOR = 0xC0100000,
        USBD_STATUS_BAD_DESCRIPTOR_BLEN = 0xC0100001,
        USBD_STATUS_BAD_DESCRIPTOR_TYPE = 0xC0100002,
        USBD_STATUS_BAD_INTERFACE_DESCRIPTOR = 0xC0100003,
        USBD_STATUS_BAD_ENDPOINT_DESCRIPTOR = 0xC0100004,
        USBD_STATUS_BAD_INTERFACE_ASSOC_DESCRIPTOR = 0xC0100005,
        USBD_STATUS_BAD_CONFIG_DESC_LENGTH = 0xC0100006,
        USBD_STATUS_BAD_NUMBER_OF_INTERFACES = 0xC0100007,
        USBD_STATUS_BAD_NUMBER_OF_ENDPOINTS = 0xC0100008,
        USBD_STATUS_BAD_ENDPOINT_ADDRESS = 0xC0100009,
    }

    public enum FileType : uint
    {
        FileTypeChar = 0x0002,
        FileTypeDisk = 0x0001,
        FileTypePipe = 0x0003,
        FileTypeRemote = 0x8000,
        FileTypeUnknown = 0x0000,
    }
}
