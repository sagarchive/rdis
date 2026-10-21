import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.PrintWriter;

public class DecompileAll extends GhidraScript {
    private static String esc(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': break;
                case '\t': b.append("\\t"); break;
                default: if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(getScriptArgs()[0])) {
            w.println("{");
            boolean first = true;
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                if (f.isExternal() || f.isThunk()) continue;
                DecompileResults r = di.decompileFunction(f, 60, monitor);
                if (!r.decompileCompleted() || r.getDecompiledFunction() == null) continue;
                if (!first) w.println(",");
                first = false;
                w.printf("%s: %s", esc(f.getName()), esc(r.getDecompiledFunction().getC()));
            }
            w.println();
            w.println("}");
        }
    }
}
