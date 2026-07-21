    gum_interceptor_replace (interceptor, gum_original_signal,
        gum_exceptor_backend_replacement_signal, NULL, &options);
    gum_interceptor_replace (interceptor, gum_original_sigaction,
        gum_exceptor_backend_replacement_sigaction, NULL, &options);
