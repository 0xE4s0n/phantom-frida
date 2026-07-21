'use strict';

import Java from 'frida-java-bridge';

// Structured acceptance test: native stealth markers, Java bridge, and a live hook.
setTimeout(function () {
    var failures = [];
    var javaAvailable = typeof Java !== 'undefined' && Java.available;

    function fail(label, error) {
        var detail = error === undefined ? '' : ': ' + String(error);
        failures.push(label + detail);
        console.log('[FAIL] ' + label + detail);
    }

    function finish() {
        send({
            type: 'phantom-frida-result',
            failures: failures,
            javaAvailable: javaAvailable
        });
    }

    // 1. /proc/self/maps
    try {
        var mapsFile = new File('/proc/self/maps', 'r');
        var maps = mapsFile.readAllText();
        mapsFile.close();
        var mapLines = maps.split('\n');
        for (var mapIndex = 0; mapIndex < mapLines.length; mapIndex++) {
            if (mapLines[mapIndex].toLowerCase().indexOf('frida') >= 0) {
                fail('maps contains frida', mapLines[mapIndex].trim());
            }
        }
    } catch (error) {
        fail('maps scan failed', error);
    }

    // 2. Native thread names
    try {
        var threads = Process.enumerateThreads();
        for (var threadIndex = 0; threadIndex < threads.length; threadIndex++) {
            try {
                var commFile = new File(
                    '/proc/self/task/' + threads[threadIndex].id + '/comm',
                    'r'
                );
                var threadName = commFile.readAllText().trim();
                commFile.close();
                var loweredThread = threadName.toLowerCase();
                if (
                    loweredThread.indexOf('frida') >= 0 ||
                    threadName === 'gmain' ||
                    threadName === 'gdbus' ||
                    threadName === 'gum-js-loop' ||
                    threadName === 'pool-spawner'
                ) {
                    fail('suspicious native thread', threadName);
                }
            } catch (error) {
                fail('native thread scan failed', error);
            }
        }
    } catch (error) {
        fail('thread enumeration failed', error);
    }

    // 3. Loaded modules
    try {
        var modules = Process.enumerateModules();
        for (var moduleIndex = 0; moduleIndex < modules.length; moduleIndex++) {
            if (modules[moduleIndex].name.toLowerCase().indexOf('frida') >= 0) {
                fail('module contains frida', modules[moduleIndex].name);
            }
        }
    } catch (error) {
        fail('module enumeration failed', error);
    }

    // 4. Export renamed during the two-pass build
    try {
        var agentMain = Module.findGlobalExportByName('frida_agent_main');
        if (agentMain !== null) {
            fail('frida_agent_main export is visible', agentMain);
        }
    } catch (error) {
        fail('agent export lookup failed', error);
    }

    if (!javaAvailable) {
        fail('Java bridge unavailable');
        finish();
        return;
    }

    try {
        Java.perform(function () {
            try {
                var classes = Java.enumerateLoadedClassesSync();
                if (classes.length === 0) {
                    fail('Java class enumeration returned no classes');
                }

                var requiredClasses = [
                    'java.lang.String',
                    'android.app.Activity',
                    'javax.crypto.Cipher',
                    'android.content.SharedPreferences',
                    'java.net.URL'
                ];
                for (var classIndex = 0; classIndex < requiredClasses.length; classIndex++) {
                    try {
                        Java.use(requiredClasses[classIndex]);
                    } catch (error) {
                        fail('Java.use(' + requiredClasses[classIndex] + ') failed', error);
                    }
                }

                try {
                    var Activity = Java.use('android.app.Activity');
                    var onCreate = Activity.onCreate.overload('android.os.Bundle');
                    onCreate.implementation = function (bundle) {
                        return onCreate.call(this, bundle);
                    };
                } catch (error) {
                    fail('Activity.onCreate hook failed', error);
                }

                try {
                    var Thread = Java.use('java.lang.Thread');
                    var threadSet = Thread.getAllStackTraces();
                    var iterator = threadSet.keySet().iterator();
                    while (iterator.hasNext()) {
                        var javaThreadName = iterator.next().getName();
                        var loweredJavaThread = javaThreadName.toLowerCase();
                        if (
                            loweredJavaThread.indexOf('frida') >= 0 ||
                            javaThreadName === 'gmain' ||
                            javaThreadName === 'gdbus' ||
                            javaThreadName === 'gum-js-loop' ||
                            javaThreadName === 'pool-spawner'
                        ) {
                            fail('suspicious Java thread', javaThreadName);
                        }
                    }
                } catch (error) {
                    fail('Java thread scan failed', error);
                }

                try {
                    var Runtime = Java.use('java.lang.Runtime');
                    var process = Runtime.getRuntime().exec('cat /proc/self/maps');
                    var input = process.getInputStream();
                    var buffer = Java.array('byte', new Array(65536).fill(0));
                    var javaMaps = '';
                    var bytesRead;
                    while ((bytesRead = input.read(buffer)) > 0) {
                        for (var byteIndex = 0; byteIndex < bytesRead; byteIndex++) {
                            javaMaps += String.fromCharCode(buffer[byteIndex] & 0xff);
                        }
                    }
                    input.close();
                    if (javaMaps.toLowerCase().indexOf('frida') >= 0) {
                        fail('Java maps scan contains frida');
                    }
                } catch (error) {
                    fail('Java maps scan failed', error);
                }
            } catch (error) {
                fail('Java acceptance callback failed', error);
            }
            finish();
        });
    } catch (error) {
        fail('Java.perform failed', error);
        finish();
    }
}, 2000);
