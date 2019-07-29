import pypsexec_mod.pypsexec.client;

client = pypsexec_mod.pypsexec.client.Client(server="192.168.1.1", username="user", password="pass", encrypt=True, obscure=True, sharename="C$");

try:
    client.connect();
    client.create_service();
    args = None;
    exe = "powershell.exe";

    while True:
        args = input("Command to run: ");
        if args:
            if args.find("exit") > -1:
                exit(0);
            else:
                if exe.find("cmd") > -1:
                    args = "/c {}".format(args);

                stdout, stderr, rc = client.run_executable(executable=exe, arguments=args);
                print(stdout.decode("UTF-8"));
                print(stderr.decode("UTF-8"));
        else:
            print("bad char");
except Exception as err:
    print(err);
finally:
    client.remove_service();
    client.disconnect();
