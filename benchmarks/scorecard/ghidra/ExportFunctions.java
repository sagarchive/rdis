import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.PrintWriter;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        try (PrintWriter w = new PrintWriter(out)) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            w.println("[");
            boolean first = true;
            while (it.hasNext()) {
                Function f = it.next();
                if (!first) {
                    w.println(",");
                }
                first = false;
                w.printf("{\"addr\": %d, \"name\": \"%s\", \"size\": %d, \"external\": %b}",
                        f.getEntryPoint().getOffset(), f.getName().replace("\"", "'"), f.getBody().getNumAddresses(),
                        f.isExternal());
            }
            w.println();
            w.println("]");
        }
    }
}
