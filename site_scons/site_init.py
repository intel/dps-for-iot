def DPS(env):
    bld = Builder(action=build_function)
    env.Append(BUILDERS = {'SwigDox' : bld})

import swig_doc
def build_function(target, source, env):
    for t in target:
        if "py" in str(t):
            swig_doc.generate("py", source[0].srcnode().path, t.path)
        elif "js" in str(t):
            swig_doc.generate("js", source[0].srcnode().path, t.path)
    return None
