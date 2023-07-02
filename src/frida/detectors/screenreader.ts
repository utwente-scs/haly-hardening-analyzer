import { addJavaPreHook } from "../hooks/java";
import { logJavaFunction } from "../inc/log";

addJavaPreHook('android.view.SurfaceView::setSecure', ['boolean'], (data) => {
    if (data.args[0] == true)  {
        logJavaFunction(data)
    }
});

addJavaPreHook('android.view.Window::setFlags', ['int', 'int'], (data) => {
    // Check if FLAG_SECURE (0x2000) is set
    if ((data.args[0] & 0x2000) != 0 && (data.args[1] & 0x2000) != 0) {
        logJavaFunction(data)
    }
});

