Java.perform(function () {
    console.log("jscode start");

    过环境检测

    var rootCheckfunc = Java.use("g5.j");
    rootCheckfunc['a'].implementation = function ()
    {
        console.log("env checking bypassed successfully");
        return true;
    }







    // 改wifi MAC地址，直接无限试用
    let NetworkInterface = Java.use("java.net.NetworkInterface");
    NetworkInterface["getHardwareAddress"].implementation = function ()
    {
        let result = this["getHardwareAddress"]();
        result = Java.array('byte', [ -10,-16,82,-113,-84,-20 ]);
        console.log(`getHardwareAddress.native_get result=${result}`);
        return result;
    };



});