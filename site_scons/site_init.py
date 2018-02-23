def DPS(env):
    bld = Builder(action=build_function)
    env.Append(BUILDERS = {'SwigDox' : bld})

import swig_doc
def build_function(target, source, env):
    for t in target:
        if "py" in str(t):
            swig_doc.generate("py", str(source[0]), str(t))
        elif "js" in str(t):
            swig_doc.generate("js", str(source[0]), str(t))
    return None
