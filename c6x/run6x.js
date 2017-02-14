#!/usr/bin/env dss.sh
//
// Debug Server Scripting C6x launcher.
//

importPackage(Packages.com.ti.debug.engine.scripting);
importPackage(Packages.com.ti.ccstudio.scripting.environment);
importPackage(Packages.java.lang);

if (arguments.length == 0) {
    // Extract script name from eclipse
    var regex = new RegExp("-dss\\.rhinoArgs\n(.*)");
    var matches = regex.exec(environment["eclipse.commands"]);

    System.err.println("Usage: " + matches[1] + " executable [args]");
    System.err.println();
    System.err.println("You're also required to set CCSTARGETCONFIG " +
                       "environment variable to appoint");
    System.err.println("proper .ccxml file, customarily one of " +
                       "$HOME/ti/CCSTargetConfigurations/*.ccxml");
    quit(1);
}

try {
    var prog = arguments[0];
    var script = ScriptingEnvironment.instance();

    var debugServer = script.getServer("DebugServer.1");

    // CCSTARGETCONFIG environment variable should point at proper .ccxml,
    // customarily one of $HOME/ti/CCSTargetConfigurations/*.ccxml.
    debugServer.setConfig(System.getenv("CCSTARGETCONFIG"));

    var debugSession = debugServer.openSession("*", "*");

    // Redirect GEL output to |prog|.gel file, so that it doesn't clobber
    // standard output from the program...
    var dot = prog.lastIndexOf(".");
    var gel_out = prog + ".gel";
    if (dot > 0) {
        gel_out = prog.substr(0,dot) + ".gel";
    }
    debugSession.expression.evaluate('GEL_EnableFileOutput("'
                                      + gel_out + '", 0, 0)');

    debugSession.target.connect();

    // It should be noted that "current working directory" for program
    // executed on the target system is one where |prog| resides, and
    // not where script executed [as one would expect]...
    debugSession.memory.loadProgram(prog, arguments);

    // Pull exit()'s address and set breakpoint, then just execute till
    // it's reached...
    var exitAddr = debugSession.symbol.getAddress("exit");
    debugSession.breakpoint.add(exitAddr);

    while (1) {
        debugSession.target.run();

        var PC = debugSession.expression.evaluate("PC");
        if (PC == exitAddr) {
            break;
        }
    }

    // Snatch value passed to exit(), so that it can be passed down to
    // shell as exit code from this script...
    var exitCode = debugSession.expression.evaluate("A4");

    // Last run to termination...
    debugSession.target.run();
    // Clean up...
    debugSession.terminate();
    debugServer.stop();

    // It should be noted that there is kind of a bug in C6x run-time.
    // Return value from main() is not passed to last implicit exit()
    // call [as it would on other systems], but instead constant 1 is
    // passed, which conventionally indicates an error. So that if one
    // wants to pass specific exit code, or even 0 indicating "success",
    // one has to call exit() explicitly instead of relying on value
    // returned by main()...
    quit(exitCode);

} catch (e) {
    // We catch everything, because default handler terminates script with
    // "success" exit code upon exception...
    System.err.println(e.rhinoException);
    quit(139);
}
