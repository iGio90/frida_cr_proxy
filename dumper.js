var ENCRYPTION = 0x09C0C7;
var ENCRYPTION_SEND = 0x326CC0;
var DECRYPTION = 0x09C168;

inject();

function ba2hex(bufArray) {
    var uint8arr = new Uint8Array(bufArray);
    if (!uint8arr) {
        return '';
    }

    var hexStr = '';
    for (var i = 0; i < uint8arr.length; i++) {
        var hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }

    return hexStr.toUpperCase();
}

function inject() {
    Process.enumerateModules({
        onMatch: function (module) {

            if (module.name === "libg.so") {
                var base = module.base;
                var pt1 = ptr(parseInt(base) + ENCRYPTION);
                var pt2 = ptr(parseInt(base) + DECRYPTION);
                var pt3 = ptr(parseInt(base) + ENCRYPTION_SEND);

                var theContent = null;
                Interceptor.attach(pt1, {
                    onEnter: function (args) {
                        var len = parseInt(args[2]);
                        theContent = ba2hex(Memory.readByteArray(ptr(parseInt(args[0]) + 32), len - 32));
                    },
                    onLeave: function (retval) {
                    }
                });
                Interceptor.attach(pt3, {
                    onEnter: function (args) {
                        if (theContent != null) {
                            msgId = parseInt("0x" + ba2hex(Memory.readByteArray(args[1], 2)));
                            if (msgId == 10101) {
                                theContent = theContent.substring(96);
                            }
                            var msg = {
                                "deliever": "client",
                                "id": msgId,
                                "content": theContent
                            }
                            send(msg);
                            theContent = null;
                        }
                    },
                    onLeave: function (retval) {
                    }
                });

                var rcvHeaders = null;
                Interceptor.attach(Module.findExportByName("libg.so", "recv"), {
                    onEnter: function (args) {
                        if (parseInt(args[2]) == 7) {
                            rcvHeaders = args[1];
                        }
                    },
                    onLeave: function (retval) {
                    }
                });
                var arg0;
                var arglen;
                Interceptor.attach(pt2, {
                    onEnter: function (args) {
                        arg0 = args[0];
                        arglen = parseInt(args[2]);
                    },
                    onLeave: function (retval) {
                        var msg = {
                            "deliever": "server",
                                "id": parseInt("0x" + ba2hex(Memory.readByteArray(rcvHeaders, 2))),
                            "content": ba2hex(Memory.readByteArray(ptr(parseInt(arg0) + 32), arglen - 32))
                        }
                        send(msg);
                    }
                });
            }
        },
        onComplete: function () {
        }
    });
}