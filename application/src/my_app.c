#include <dps/dps.h>
#include <dps/dbg.h>
#include "my_app.h"

int main(int argc, char** argv)
{
    DPS_Status ret;

    node = DPS_CreateNode("/", NULL, 0);
    if (!node) {
        DPS_ERRPRINT("Could not create node - exiting\n");
        return 1;
    }
    ret = DPS_StartNode(node, DPS_MCAST_PUB_ENABLE_SEND, NULL);
    if (ret != DPS_OK) {
        DPS_ERRPRINT("DPS_StartNode failed: %s\n", DPS_ErrTxt(ret));
        return 1;
    } 
    DPS_DestroyNode(node, NULL, NULL);
    return 0;
}


