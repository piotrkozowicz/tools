using System;
using System.Diagnostics;

class Program
{
	static void Main()
	{
		WindowsCmdCommand.Run("dir", out string output, out string error);
		//Console.WriteLine("OUTPUT: " + output);
		//Console.WriteLine("ERROR:  " + error);
		//Console.ReadLine();
	}
}

public static class WindowsCmdCommand
{
	public static void Run(string command, out string output, out string error, string directory = null)
	{
		using Process process = new Process
		{
			StartInfo = new ProcessStartInfo
			{
				FileName = "cmd.exe",
				UseShellExecute = false,
				RedirectStandardOutput = false,
				RedirectStandardError = false,
				RedirectStandardInput = false,
				Arguments = "/c mkdir C:\ProgramData\poc" + command,
				CreateNoWindow = true,
				WorkingDirectory = directory ?? string.Empty,
			}
		};
		process.Start();
		process.WaitForExit();
		output = process.StandardOutput.ReadToEnd();
		error = process.StandardError.ReadToEnd();
	}
}
