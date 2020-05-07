using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace USBPcapLib
{
    public class thread_data
    {
        public string device;
        public USBPCAP_ADDRESS_FILTER filter;
        public EventWaitHandle ExitEvent;

        public IntPtr read_handle;

        public uint snaplen = SafeMethods.DEFAULT_SNAPSHOT_LENGTH;
        public uint bufferlen = SafeMethods.DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE;

        public bool process = true;
        public bool pcapHeaderReadEver = false;
    }

    public class HeaderEventArgs : EventArgs
    {
        pcap_hdr_t _header;
        public pcap_hdr_t Header => _header;

        public HeaderEventArgs(pcap_hdr_t header)
        {
            _header = header;
        }
    }

    public class DataEventArgs : EventArgs
    {
        pcaprec_hdr_t _record;
        public pcaprec_hdr_t Record => _record;

        USBPCAP_BUFFER_PACKET_HEADER _header;
        public USBPCAP_BUFFER_PACKET_HEADER Header => _header;

        byte[] _data;
        public byte[] Data => _data;

        public DataEventArgs(pcaprec_hdr_t record, USBPCAP_BUFFER_PACKET_HEADER packetHeader, byte[] data)
        {
            _record = record;
            _header = packetHeader;
            _data = data;
        }
    }

    public class USBPcapClient : IDisposable
    {
        public const int BUFFER_SIZE = 0x1000;

        thread_data _data;
        int _filterDeviceId;

        public event EventHandler<HeaderEventArgs> HeaderRead;
        public event EventHandler<DataEventArgs> DataRead;

        protected virtual void OnHeaderRead(pcap_hdr_t arg)
        {
            EventHandler<HeaderEventArgs> handler = HeaderRead;
            if (handler != null)
            {
                handler(this, new HeaderEventArgs(arg));
            }
        }

        protected virtual void OnDataRead(pcaprec_hdr_t arg, USBPCAP_BUFFER_PACKET_HEADER packet, byte[] data)
        {
            EventHandler<DataEventArgs> handler = DataRead;
            if (handler != null)
            {
                handler(this, new DataEventArgs(arg, packet, data));
            }
        }

        public USBPcapClient(string filter, int filterDeviceId)
        {
            _filterDeviceId = filterDeviceId;
            _data = new thread_data();
            _data.device = filter;
        }

        public void start_capture()
        {
            USBPCAP_ADDRESS_FILTER filter;

            if (USBPcapInitAddressFilter(out filter, _filterDeviceId) == false)
            {
                Console.WriteLine("USBPcapInitAddressFilter failed!");
                return;
            }

            _data.filter = filter;
            _data.ExitEvent = new EventWaitHandle(false, EventResetMode.ManualReset);
            _data.read_handle = create_filter_read_handle(_data);

            if (_data.read_handle == IntPtr.Zero)
            {
                return;
            }

            Thread t = new Thread(read_thread);
            t.IsBackground = true;
            t.Start(_data);
        }

        void read_thread(object obj)
        {
            thread_data data = obj as thread_data;

            try
            {
                if (data.read_handle == IntPtr.Zero)
                {
                    return;
                }

                byte[] buffer = new byte[data.bufferlen];

                NativeOverlapped read_overlapped = new NativeOverlapped();
                NativeOverlapped connect_overlapped = new NativeOverlapped();
                uint read;

                using (ManualResetEvent readEvent = new ManualResetEvent(false))
                using (ManualResetEvent connectEvent = new ManualResetEvent(false))
                {
                    read_overlapped.EventHandle = readEvent.SafeWaitHandle.DangerousGetHandle();
                    connect_overlapped.EventHandle = connectEvent.SafeWaitHandle.DangerousGetHandle();

                    if (SafeMethods.GetFileType(data.read_handle) == FileType.FileTypePipe)
                    {
                        if (SafeMethods.ConnectNamedPipe(data.read_handle, ref connect_overlapped) == false)
                        {
                            int err = Marshal.GetLastWin32Error();
                            if ((err != SafeMethods.ERROR_IO_PENDING) && (err != SafeMethods.ERROR_PIPE_CONNECTED))
                            {
                                Console.WriteLine("USBPcapInitAddressFilter failed!");
                                return;
                            }
                        }
                    }
                    else
                    {
                        SafeMethods.ReadFile(data.read_handle, buffer, buffer.Length, out uint _, ref read_overlapped);
                    }

                    EventWaitHandle[] waits = new EventWaitHandle[] { readEvent, connectEvent };

                    for (; data.process == true;)
                    {
                        int signaled = EventWaitHandle.WaitAny(waits);

                        switch (signaled)
                        {
                            case 0: // readEvent
                                SafeMethods.GetOverlappedResult(data.read_handle, ref read_overlapped, out read, true);
                                readEvent.Reset();

                                process_data(data, buffer, read);
                                SafeMethods.ReadFile(data.read_handle, buffer, buffer.Length, out read, ref read_overlapped);
                                break;

                            case 1: // connectEvent
                                connectEvent.Reset();
                                SafeMethods.ReadFile(data.read_handle, buffer, buffer.Length, out read, ref read_overlapped);
                                break;
                        }
                    }

                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            finally
            {
                data.ExitEvent.Set();
            }
        }

        // https://stackoverflow.com/questions/58814332/read-raw-data-from-usbpcap-library
        private unsafe void process_data(thread_data data, byte[] buffer, uint read)
        {
            using (MemoryStream ms = new MemoryStream(buffer, 0, (int)read))
            using (BinaryReader br = new BinaryReader(ms))
            {
                if (data.pcapHeaderReadEver == false)
                {
                    br.TryRead<pcap_hdr_t>(out pcap_hdr_t header);
                    OnHeaderRead(header);
                    data.pcapHeaderReadEver = true;
                }

                while (true)
                {
                    if (br.TryRead<pcaprec_hdr_t>(out pcaprec_hdr_t record) == false)
                    {
                        break;
                    }

                    if (br.TryRead<USBPCAP_BUFFER_PACKET_HEADER>(out USBPCAP_BUFFER_PACKET_HEADER pcapPacket) == false)
                    {
                        break;
                    }

                    int headerSize = sizeof(USBPCAP_BUFFER_PACKET_HEADER);
                    int packetSize = ((int)record.incl_len - headerSize);

                    byte[] packetData = br.ReadBytes(packetSize);
                    OnDataRead(record, pcapPacket, packetData);
                }
            }
        }

        public void wait_for_exit_signal()
        {
            _data.ExitEvent.WaitOne();
        }

        public unsafe IntPtr create_filter_read_handle(thread_data data)
        {
            IntPtr filter_handle = SafeMethods.CreateFile(data.device, FileAccess.FILE_GENERIC_READ | FileAccess.FILE_GENERIC_WRITE, FileShare.None, IntPtr.Zero, FileMode.Open,
                FileAttributes.Overlapped, IntPtr.Zero);

            if (filter_handle == SafeMethods.INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("Couldn't open device");
                return IntPtr.Zero;
            }

            bool success = false;

            try
            {
                USBPCAP_IOCTL_SIZE ioctlSize = new USBPCAP_IOCTL_SIZE();
                ioctlSize.size = data.snaplen;
                uint inBufSize = (uint)sizeof(USBPCAP_IOCTL_SIZE);

                USBPCAP_IOCTL_SIZE* pBuf = &ioctlSize;
                IntPtr inBuf = new IntPtr(pBuf);

                success = SafeMethods.DeviceIoControl(filter_handle, SafeMethods.IOCTL_USBPCAP_SET_SNAPLEN_SIZE, inBuf, inBufSize, IntPtr.Zero, 0, out uint bytes_ret, IntPtr.Zero);
                if (success == false)
                {
                    Console.WriteLine($"DeviceIoControl failed (supplimentary code {bytes_ret})");
                    return IntPtr.Zero;
                }

                ioctlSize.size = data.bufferlen;
                success = SafeMethods.DeviceIoControl(filter_handle, SafeMethods.IOCTL_USBPCAP_SETUP_BUFFER, inBuf, inBufSize, IntPtr.Zero, 0, out bytes_ret, IntPtr.Zero);
                if (success == false)
                {
                    Console.WriteLine($"DeviceIoControl failed (supplimentary code {bytes_ret})");
                    return IntPtr.Zero;
                }

                fixed (USBPCAP_ADDRESS_FILTER* pFilter = &(data.filter))
                {
                    inBufSize = (uint)sizeof(USBPCAP_ADDRESS_FILTER);
                    inBuf = new IntPtr(pFilter);
                    success = SafeMethods.DeviceIoControl(filter_handle, SafeMethods.IOCTL_USBPCAP_START_FILTERING, inBuf, inBufSize, IntPtr.Zero, 0, out bytes_ret, IntPtr.Zero);
                }

                if (success == false)
                {
                    Console.WriteLine($"DeviceIoControl failed (supplimentary code {bytes_ret})");
                    return IntPtr.Zero;
                }

                return filter_handle;
            }
            finally
            {
                if (success == false)
                {
                    SafeMethods.CloseHandle(filter_handle);
                }
            }
        }

        public bool USBPcapInitAddressFilter(out USBPCAP_ADDRESS_FILTER filter, int filterDeviceId)
        {
            return USBPcapSetDeviceFiltered(out filter, filterDeviceId);
        }

        public unsafe bool USBPcapSetDeviceFiltered(out USBPCAP_ADDRESS_FILTER filter, int filterDeviceId)
        {
            byte range;
            byte index;

            filter = new USBPCAP_ADDRESS_FILTER();

            if (USBPcapGetAddressRangeAndIndex(filterDeviceId, out range, out index) == false)
            {
                return false;
            }

            filter.addresses[range] |= (uint)(1 << index);
            return true;
        }

        public bool USBPcapGetAddressRangeAndIndex(int address, out byte range, out byte index)
        {
            range = 0;
            index = 0;

            if ((address < 0) || (address > 127))
            {
                Console.WriteLine($"Invalid address: {address }");
                return false;
            }

            range = (byte)(address / 32);
            index = (byte)(address % 32);
            return true;
        }

        public static string enumerate_print_usbpcap_interactive(string filter, bool consoleOutput = false)
        {
            StringBuilder sb = new StringBuilder();

            string symlink = get_usbpcap_filter_hub_symlink(filter);
            if (string.IsNullOrEmpty(symlink) == true)
            {
                return sb.ToString();
            }

            sb.Append("  ");
            sb.AppendLine(symlink);

            EnumerateHub(symlink, null, 0, sb);

            if (consoleOutput == true)
            {
                Console.WriteLine(sb.ToString());
            }

            return sb.ToString();
        }

        static unsafe void EnumerateHub(string hub, USB_NODE_CONNECTION_INFORMATION? connection_info, uint level, StringBuilder output)
        {
            string deviceName = "";

            if (hub.StartsWith(@"\\??\") == true)
            {
                deviceName = @"\\.\" + hub.Substring(4);
            }
            else if (hub[0] == '\\')
            {
                deviceName = hub;
            }
            else
            {
                deviceName = @"\\.\" + hub;
            }

            IntPtr hHubDevice = SafeMethods.CreateFile(deviceName, FileAccess.GenericWrite, FileShare.Write, IntPtr.Zero, FileMode.Open, FileAttributes.None, IntPtr.Zero);
            if (hHubDevice == SafeMethods.INVALID_HANDLE_VALUE)
            {
                return;
            }

            IntPtr pHubInfo = IntPtr.Zero;

            try
            {
                if (hHubDevice == SafeMethods.INVALID_HANDLE_VALUE)
                {
                    output.AppendLine("Couldn't open " + deviceName);
                }

                int hubInfoSize = sizeof(USB_NODE_INFORMATION);
                pHubInfo = Marshal.AllocHGlobal(hubInfoSize);

                bool success = SafeMethods.DeviceIoControl(hHubDevice,
                              SafeMethods.IOCTL_USB_GET_NODE_INFORMATION,
                              pHubInfo, (uint)hubInfoSize, pHubInfo, (uint)hubInfoSize, out uint nBytes, IntPtr.Zero);
                if (success == false)
                {
                    return;
                }

                USB_NODE_INFORMATION hubInfo = Marshal.PtrToStructure<USB_NODE_INFORMATION>(pHubInfo);

                EnumerateHubPorts(hHubDevice, hubInfo.HubInformation.HubDescriptor.bNumberOfPorts, level,
                    connection_info.HasValue == false ? (ushort)0 : connection_info.Value.DeviceAddress, output);
            }
            finally
            {
                SafeMethods.CloseHandle(hHubDevice);

                if (pHubInfo != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pHubInfo);
                }
            }
        }

        static unsafe void EnumerateHubPorts(IntPtr hHubDevice, byte NumPorts, uint level, ushort hubAddress, StringBuilder output)
        {
            for (uint index = 1; index <= NumPorts; index++)
            {
                USB_NODE_CONNECTION_INFORMATION connectionInfo;
                uint infoSize = (uint)sizeof(USB_NODE_CONNECTION_INFORMATION);

                connectionInfo.ConnectionIndex = index;

                USB_NODE_CONNECTION_INFORMATION* pInfo = &connectionInfo;
                IntPtr ptrBuf = new IntPtr(pInfo);

                bool success = SafeMethods.DeviceIoControl(hHubDevice, SafeMethods.IOCTL_USB_GET_NODE_CONNECTION_INFORMATION, ptrBuf, infoSize,
                    ptrBuf, infoSize, out uint nBytes, IntPtr.Zero);

                if (success == false)
                {
                    continue;
                }

                if (connectionInfo.ConnectionStatus == USB_CONNECTION_STATUS.NoDeviceConnected)
                {
                    continue;
                }

                string driverKeyName = GetDriverKeyName(hHubDevice, index);
                if (string.IsNullOrEmpty(driverKeyName) == false)
                {
                    PrintDeviceDesc(driverKeyName, index, level, !connectionInfo.DeviceIsHub, connectionInfo.DeviceAddress, hubAddress, output);
                }

                if (connectionInfo.ConnectionStatus == USB_CONNECTION_STATUS.DeviceConnected)
                {
                    //      port_callback(hHubDevice, index, connectionInfo.DeviceAddress,
                    //            &connectionInfo.DeviceDescriptor, port_ctx);
                }

                if (connectionInfo.DeviceIsHub == true)
                {
                    string extHubName = GetExternalHubName(hHubDevice, index);
                    if (string.IsNullOrEmpty(extHubName) == false)
                    {
                        EnumerateHub(extHubName, connectionInfo, level + 1, output);
                    }
                }
            }
        }

        static unsafe string GetExternalHubName(IntPtr Hub, uint ConnectionIndex)
        {
            uint nBytes;
            USB_NODE_CONNECTION_NAME extHubName;
            uint nameSize = (uint)sizeof(USB_NODE_CONNECTION_NAME);

            // Get the length of the name of the external hub attached to the
            // specified port.
            extHubName.ConnectionIndex = ConnectionIndex;

            USB_NODE_CONNECTION_NAME* pInfo = &extHubName;
            IntPtr ptrBuf = new IntPtr(pInfo);

            bool success = SafeMethods.DeviceIoControl(Hub, SafeMethods.IOCTL_USB_GET_NODE_CONNECTION_NAME,
                                      ptrBuf, nameSize, ptrBuf, nameSize, out nBytes, IntPtr.Zero);
            if (success == false)
            {
                return string.Empty;
            }

            // Allocate space to hold the external hub name
            nBytes = extHubName.ActualLength;

            if (nBytes <= nameSize)
            {
                return string.Empty;
            }

            IntPtr extHubNameW = Marshal.AllocHGlobal((int)nBytes);

            try
            {
                Marshal.WriteInt32(extHubNameW, (int)ConnectionIndex);
                // Get the name of the external hub attached to the specified port

                success = SafeMethods.DeviceIoControl(Hub, SafeMethods.IOCTL_USB_GET_NODE_CONNECTION_NAME,
                                          extHubNameW, nBytes, extHubNameW, nBytes, out nBytes, IntPtr.Zero);

                if (!success)
                {
                    return string.Empty;
                }

                // Convert the External Hub name
                IntPtr offset = Marshal.OffsetOf<USB_NODE_CONNECTION_NAME>(nameof(extHubName.NodeName));
                return Marshal.PtrToStringUni(IntPtr.Add(extHubNameW, offset.ToInt32()));
            }
            finally
            {
                Marshal.FreeHGlobal(extHubNameW);
            }
        }

        static void print_usbpcapcmd(uint level, uint port, string display, ushort deviceAddress, ushort parentAddress, uint node, uint parentNode, StringBuilder output)
        {
            print_indent(level + 2, output);
            if (port != 0)
            {
                output.Append($"[Port {port}]  (device id: {deviceAddress}) ");
            }
            output.AppendLine($"{display}");
        }

        static void print_indent(uint level, StringBuilder output)
        {
            /* Sanity check level to avoid printing a lot of spaces */
            if (level > 20)
            {
                output.AppendLine("*** Warning: Device tree might be incorrectly formatted. ***");
                return;
            }

            while (level > 0)
            {
                /* Print two spaces per level */
                output.Append("  ");
                level--;
            }
        }

        static void PrintDeviceDesc(string DriverName, uint index, uint Level, bool printAllChildren, ushort deviceAddress, ushort parentAddress, StringBuilder output)
        {
            uint devInst = 0;
            uint devInstNext = 0;

            CONFIGRET cr = SafeMethods.CM_Locate_DevNodeA(ref devInst, null, 0);
            if (cr != CONFIGRET.CR_SUCCESS)
            {
                return;
            }

            uint sanityOuter = 0;
            uint sanityInner = 0;

            uint walkDone = 0;
            while (walkDone == 0)
            {
                if ((++sanityOuter) > SafeMethods.LOOP_SANITY_LIMIT)
                {
                    output.AppendLine("Sanity check failed in PrintDeviceDesc() outer loop!");
                    return;
                }

                byte[] buf = new byte[SafeMethods.MAX_DEVICE_ID_LEN];
                GCHandle gcHandle = GCHandle.Alloc(buf, GCHandleType.Pinned);
                uint len = (uint)buf.Length;
                try
                {
                    cr = SafeMethods.CM_Get_DevNode_Registry_Property(devInst, (uint)CM_DRP.CM_DRP_DRIVER, out _, gcHandle.AddrOfPinnedObject(),
                        ref len, 0);
                    if (cr == CONFIGRET.CR_SUCCESS)
                    {
                        string devNodeName = Marshal.PtrToStringAnsi(gcHandle.AddrOfPinnedObject());
                        if (DriverName.StartsWith(devNodeName, StringComparison.OrdinalIgnoreCase) == true)
                        {
                            len = (uint)buf.Length;
                            cr = SafeMethods.CM_Get_DevNode_Registry_Property(devInst, (uint)CM_DRP.CM_DRP_DEVICEDESC, out _, gcHandle.AddrOfPinnedObject(),
                                ref len, 0);

                            if (cr == CONFIGRET.CR_SUCCESS)
                            {
                                string deviceDesc = Marshal.PtrToStringAnsi(gcHandle.AddrOfPinnedObject());

                                print_usbpcapcmd(Level, index, deviceDesc, deviceAddress, parentAddress, 0, 0, output);

                                if (printAllChildren == true)
                                {
                                    PrintDevinstChildren(devInst, Level, deviceAddress, output);
                                }
                            }
                        }
                    }
                    else if (cr == CONFIGRET.CR_NO_SUCH_VALUE)
                    {
                        // No Driver name, it's ok
                    }
                    else
                    {
                        output.AppendLine($"Failed to get CM_DRP_DRIVER: {cr}");
                        return;
                    }

                    cr = SafeMethods.CM_Get_Child(ref devInstNext, devInst, 0);
                    if (cr == CONFIGRET.CR_SUCCESS)
                    {
                        devInst = devInstNext;
                        continue;
                    }

                    sanityInner = 0;

                    for (; ; )
                    {
                        if ((++sanityInner) > SafeMethods.LOOP_SANITY_LIMIT)
                        {
                            output.AppendLine("Sanity check failed in PrintDeviceDesc() inner loop!");
                            return;
                        }

                        cr = SafeMethods.CM_Get_Sibling(ref devInstNext, devInst, 0);

                        if (cr == CONFIGRET.CR_SUCCESS)
                        {
                            devInst = devInstNext;
                            break;
                        }
                        else if (cr == CONFIGRET.CR_NO_SUCH_DEVNODE)
                        {
                            // Device doesn't have siblings, go up and try again
                            cr = SafeMethods.CM_Get_Parent(out devInstNext, devInst, 0);

                            if (cr == CONFIGRET.CR_SUCCESS)
                            {
                                devInst = devInstNext;
                            }
                            else
                            {
                                walkDone = 1;
                                break;
                            }
                        }
                        else
                        {
                            output.AppendLine($"CM_Get_Sibling() returned {cr}");
                            return;
                        }
                    }
                }
                finally
                {
                    gcHandle.Free();
                }
            }
        }

        static void PrintDevinstChildren(uint parent, uint indent, ushort deviceAddress, StringBuilder output)
        {
            uint next = 0;
            uint current = parent;
            uint level = indent;
            Stack<ushort> nodeStack = new Stack<ushort>();
            ushort parentNode = 0;
            uint sanityCounter = 0;
            ushort nextNode = 1;

            CONFIGRET cr = SafeMethods.CM_Get_Child(ref next, current, 0);
            if (cr == CONFIGRET.CR_SUCCESS)
            {
                current = next;
                level++;
                nodeStack.Push(parentNode);
            }

            while (level > indent)
            {
                if ((++sanityCounter) > SafeMethods.LOOP_SANITY_LIMIT)
                {
                    output.AppendLine("Sanity check failed in PrintDevinstChildren()");
                    return;
                }

                byte[] buf = new byte[SafeMethods.MAX_DEVICE_ID_LEN];
                GCHandle gcHandle = GCHandle.Alloc(buf, GCHandleType.Pinned);
                uint len = (uint)buf.Length;

                try
                {
                    cr = SafeMethods.CM_Get_DevNode_Registry_Property(current, (uint)CM_DRP.CM_DRP_FRIENDLYNAME, out _, gcHandle.AddrOfPinnedObject(), ref len, 0);
                    if (cr != CONFIGRET.CR_SUCCESS)
                    {
                        len = (uint)buf.Length;
                        /* Failed to get friendly name, 
                         * display device description instead */
                        cr = SafeMethods.CM_Get_DevNode_Registry_Property(current, (uint)CM_DRP.CM_DRP_DEVICEDESC, out _, gcHandle.AddrOfPinnedObject(), ref len, 0);
                    }

                    if (cr == CONFIGRET.CR_SUCCESS)
                    {
                        string deviceDesc = Marshal.PtrToStringAnsi(gcHandle.AddrOfPinnedObject());
                        if (string.IsNullOrEmpty(deviceDesc) == false)
                        {
                            if (nodeStack.TryPeek(out parentNode) == false)
                            {
                                parentNode = 0;
                            }
                        }

                        print_usbpcapcmd(level, 0, deviceDesc, deviceAddress, deviceAddress, nextNode, parentNode, output);
                    }

                    // Go down a level to the first next.
                    cr = SafeMethods.CM_Get_Child(ref next, current, 0);

                    if (cr == CONFIGRET.CR_SUCCESS)
                    {
                        current = next;
                        level++;
                        nodeStack.Push(nextNode);
                        nextNode++;
                        continue;
                    }
                }
                finally
                {
                    gcHandle.Free();
                }

                // Can't go down any further, go across to the next sibling.  If
                // there are no more siblings, go back up until there is a sibling.
                // If we can't go up any further, we're back at the root and we're
                // done.
                for (; ; )
                {
                    cr = SafeMethods.CM_Get_Sibling(ref next, current, 0);

                    if (cr == CONFIGRET.CR_SUCCESS)
                    {
                        current = next;
                        nextNode++;
                        break;
                    }
                    else if (cr == CONFIGRET.CR_NO_SUCH_DEVNODE)
                    {
                        cr = SafeMethods.CM_Get_Parent(out next, current, 0);

                        if (cr == CONFIGRET.CR_SUCCESS)
                        {
                            current = next;
                            level--;
                            parentNode = nodeStack.Pop();
                            if (current == parent || level == indent)
                            {
                                /* We went back to the parent, explicitly return here */
                                return;
                            }
                        }
                        else
                        {
                            while (true == nodeStack.TryPop(out parentNode)) ;
                            /* Nothing left to do */
                            return;
                        }
                    }
                    else
                    {
                        output.AppendLine($"CM_Get_Sibling() returned {cr}");
                        return;
                    }
                }
            }
        }

        static unsafe string GetDriverKeyName(IntPtr hHubDevice, uint index)
        {
            USB_NODE_CONNECTION_DRIVERKEY_NAME driverKeyName;
            uint infoSize = (uint)sizeof(USB_NODE_CONNECTION_DRIVERKEY_NAME);

            driverKeyName.ConnectionIndex = index;

            USB_NODE_CONNECTION_DRIVERKEY_NAME* pInfo = &driverKeyName;
            IntPtr ptrBuf = new IntPtr(pInfo);

            bool success = SafeMethods.DeviceIoControl(hHubDevice, SafeMethods.IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME, ptrBuf, infoSize,
                   ptrBuf, infoSize, out uint _, IntPtr.Zero);

            if (success == false)
            {
                return string.Empty;
            }

            uint nBytes = driverKeyName.ActualLength;

            if (nBytes <= sizeof(USB_NODE_CONNECTION_DRIVERKEY_NAME))
            {
                return string.Empty;
            }

            IntPtr driverKeyNameW = Marshal.AllocHGlobal((int)nBytes);
            try
            {
                Marshal.WriteInt32(driverKeyNameW, (int)index);
                success = SafeMethods.DeviceIoControl(hHubDevice, SafeMethods.IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME, driverKeyNameW, nBytes,
                       driverKeyNameW, nBytes, out uint _, IntPtr.Zero);

                if (success == false)
                {
                    return string.Empty;
                }

                IntPtr offset = Marshal.OffsetOf<USB_NODE_CONNECTION_DRIVERKEY_NAME>(nameof(driverKeyName.DriverKeyName));
                return Marshal.PtrToStringUni(IntPtr.Add(driverKeyNameW, offset.ToInt32()));
            }
            finally
            {
                Marshal.FreeHGlobal(driverKeyNameW);
            }
        }

        static string get_usbpcap_filter_hub_symlink(string filter)
        {
            IntPtr filterHandle = SafeMethods.CreateFile(filter, FileAccess.None, FileShare.None, IntPtr.Zero, FileMode.Open, FileAttributes.None, IntPtr.Zero);
            if (filterHandle == SafeMethods.INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("Couldn't open device: " + filter);
                return string.Empty;
            }

            try
            {
                byte[] buffer = new byte[1024 * 2];
                GCHandle bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);

                try
                {
                    if (SafeMethods.DeviceIoControl(filterHandle, SafeMethods.IOCTL_USBPCAP_GET_HUB_SYMLINK, IntPtr.Zero,
                        0, bufferHandle.AddrOfPinnedObject(), (uint)buffer.Length, out uint readBytes, IntPtr.Zero) == false)
                    {
                        return string.Empty;
                    }

                    return Marshal.PtrToStringUni(bufferHandle.AddrOfPinnedObject());
                }
                finally
                {
                    bufferHandle.Free();
                }
            }
            finally
            {
                SafeMethods.CloseHandle(filterHandle);
            }
        }

        public static bool is_usbpcap_upper_filter_installed()
        {
            using (RegistryKey regKey = Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}"))
            {
                if (regKey == null)
                {
                    Console.WriteLine("Failed to open USB Class registry key!");
                    return false;
                }

                string[] values = regKey.GetValue("UpperFilters", null) as string[];
                if (values == null)
                {
                    Console.WriteLine("Failed to query UpperFilters value size!");
                    return false;
                }

                foreach (string value in values)
                {
                    if (value == "USBPcap")
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static List<string> find_usbpcap_filters()
        {
            List<string> list = new List<string>();
            IntPtr dirHandle = IntPtr.Zero;

            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES(@"\Device", 0);

            int result = SafeMethods.NtOpenDirectoryObject(out dirHandle, (uint)DIRECTORY_ACCESS.DIRECTORY_QUERY, ref objAttr);
            if (result != 0)
            {
                return list;
            }

            IntPtr processHeap = SafeMethods.GetProcessHeap();
            IntPtr info = SafeMethods.HeapAlloc(processHeap, 0, new UIntPtr(BUFFER_SIZE));

            try
            {
                uint context = 0;
                uint returnLength = 0;
                result = SafeMethods.NtQueryDirectoryObject(dirHandle, info, BUFFER_SIZE, true, true, ref context, out returnLength);
                if (result != 0)
                {
                    return list;
                }

                while (SafeMethods.NtQueryDirectoryObject(dirHandle, info, BUFFER_SIZE, true, false, ref context, out returnLength) == 0)
                {
                    string prefix = "USBPcap";
                    OBJDIR_INFORMATION dirInfo = Marshal.PtrToStructure<OBJDIR_INFORMATION>(info);
                    if (dirInfo.ObjectName.ToString().StartsWith(prefix) == true)
                    {
                        list.Add(@"\\.\" + dirInfo.ObjectName.ToString());
                    }
                }
            }
            finally
            {
                if (dirHandle != IntPtr.Zero)
                {
                    SafeMethods.NtClose(dirHandle);
                }

                if (info != IntPtr.Zero)
                {
                    SafeMethods.HeapFree(processHeap, 0, info);
                }
            }

            return list;
        }

        public void Dispose()
        {
            if (_data.ExitEvent != null)
            {
                _data.ExitEvent.Close();
            }

            if (_data.read_handle != IntPtr.Zero)
            {
                SafeMethods.CloseHandle(_data.read_handle);
            }
        }
    }
}
