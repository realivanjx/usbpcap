using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace USBPcapLib
{
    internal static class HelperExtension
    {
        public static bool TryPeek<T>(this Stack<T> stack, out T item)
        {
            item = default;

            if (stack.Count == 0)
            {
                return false;
            }

            item = stack.Peek();
            return true;
        }

        public static bool TryPop<T>(this Stack<T> stack, out T item)
        {
            item = default;

            if (stack.Count == 0)
            {
                return false;
            }

            item = stack.Pop();
            return true;
        }
        public static unsafe bool TryRead<T>(this BinaryReader br, out T value) where T : unmanaged
        {
            int size = sizeof(T);
            value = default;

            byte[] buf = br.ReadBytes(size);
            if (buf.Length == 0)
            {
                return false;
            }

            GCHandle gcHandle = GCHandle.Alloc(buf, GCHandleType.Pinned);

            try
            {
                value = Marshal.PtrToStructure<T>(gcHandle.AddrOfPinnedObject());
                return true;
            }
            finally
            {
                gcHandle.Free();
            }
        }
    }
}
