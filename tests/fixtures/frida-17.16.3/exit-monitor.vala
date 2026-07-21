		construct {
			var interceptor = Gum.Interceptor.obtain ();

			unowned Gum.InvocationListener listener = this;

#if WINDOWS
			interceptor.attach ((void *) Gum.Process.find_module_by_name ("kernel32.dll").find_export_by_name ("ExitProcess"),
				listener);
#else
			var libc = Gum.Process.get_libc_module ();
			const string[] apis = {
				"exit",
				"_exit",
				"abort",
			};
			foreach (var symbol in apis) {
				interceptor.attach ((void *) libc.find_export_by_name (symbol), listener);
			}
#endif
		}
