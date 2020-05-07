using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using USBPcapLib;

namespace csUSBPcapCMD
{
    class Program
    {
        static void Main(string[] args)
        {
            List<string> filters = USBPcapClient.find_usbpcap_filters();

            if (filters.Count == 0)
            {
                Console.WriteLine("No filter control devices are available.");

                if (USBPcapClient.is_usbpcap_upper_filter_installed() == true)
                {
                    Console.WriteLine("Please reinstall USBPcapDriver.");
                }

                Console.WriteLine($@"USBPcap UpperFilter entry appears to be present.
Most likely you have not restarted your computer after installation.
It is possible to restart all USB devices to get USBPcap working without reboot.
{Environment.NewLine}WARNING:{Environment.NewLine}  Restarting all USB devices can result in data loss.
  If you are unsure please answer 'n' and reboot in order to use USBPcap.");

                return;
            }

            // how can I precisely specify a USB device to capture with tshark?
            // https://osqa-ask.wireshark.org/questions/53919/how-can-i-precisely-specify-a-usb-device-to-capture-with-tshark

            // Tracking only one USB Port in Filter using USBPcap
            // https://osqa-ask.wireshark.org/questions/63837/tracking-only-one-usb-port-in-filter-using-usbpcap
            int targetDeviceId = 0;
            int filterDeviceId = 1;

            if (args.Length >= 1)
            {
                targetDeviceId = int.Parse(args[0]);
            }

            if (args.Length >= 2)
            {
                filterDeviceId = int.Parse(args[1]);
            }

            Console.WriteLine("Following filter control devices are available:");
            string target = null;

            int i = 0;

            foreach (string filter in filters)
            {
                Console.WriteLine($"{i + 1} {filter}");

                string deviceList = USBPcapClient.enumerate_print_usbpcap_interactive(filter);
                Console.WriteLine(deviceList);

                if (targetDeviceId == i)
                {
                    target = filter;
                    break;
                }

                i++;
            }

            if (string.IsNullOrEmpty(target) == false)
            {
                using (USBPcapClient usbCapture = new USBPcapClient(target, filterDeviceId))
                {
                    usbCapture.HeaderRead += UsbCapture_HeaderRead;
                    usbCapture.DataRead += UsbCapture_DataRead;

                    usbCapture.start_capture();

                    usbCapture.wait_for_exit_signal();
                }
            }
        }

        private static void UsbCapture_HeaderRead(object sender, HeaderEventArgs e)
        {
            Console.WriteLine(e.Header.magic_number);
            Console.WriteLine(e.Header.version_major);
            Console.WriteLine(e.Header.version_minor);
            Console.WriteLine(e.Header.thiszone);
            Console.WriteLine(e.Header.sigfigs);
            Console.WriteLine(e.Header.snaplen);
            Console.WriteLine(e.Header.network);
        }

        static int _index = 1;

        private static void UsbCapture_DataRead(object sender, DataEventArgs e)
        {
            int pcapRecordDataSize = (int)e.Record.incl_len;

            //Console.WriteLine($"[{index}]");
            //Console.WriteLine(e.Record.ts_sec);
            //Console.WriteLine(e.Record.ts_usec);
            //Console.WriteLine(e.Record.incl_len);
            //Console.WriteLine(e.Record.orig_len);

            byte[] buf = e.Data;

            switch (e.Header.function)
            {
                case URB_FUNCTION.URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
                    if (e.Header.IrpDirection == IRPDierction.PDO_TO_FDO)
                    {
                        Console.Write($"[{_index}] {e.Header.bus}.{e.Header.device}.{e.Header.EndpointNumber}, {e.Header.transfer}, {e.Header.IrpDirection} : {buf.Length} - ");

                        if (e.Header.status != USBD_STATUS.USBD_STATUS_SUCCESS)
                        {
                            break;
                        }

                        if (e.Header.transfer != USBPCAP_TRANSFER_TYPE.INTERRUPT)
                        {
                            break;
                        }

                        if (buf.Length != 8)
                        {
                            break;
                        }

                        byte code = buf[2];
                        if (code == 0)
                        {
                            Console.WriteLine("key up");
                        }
                        else
                        {
                            // https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2
                            if (code >= 0x4 && code <= 0x1d)
                            {
                                char ch = (char)(code - 4 + (short)'a');
                                Console.WriteLine(ch + " pressed");
                            }
                            else
                            {
                                Console.WriteLine("Key pressed");
                            }
                        }
                    }
                    break;

                default:
                    break;
            }

            _index++;
        }
    }
}
