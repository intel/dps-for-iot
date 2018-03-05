#!/usr/bin/python
#
# Usage: swig_doc.py [py|js] build/docs/xml/index.xml
#
import os
import re
import sys
import xml.etree.ElementTree as ET
from string import Template
from textwrap import TextWrapper

ignore = [
    "DPS_CreateNode",
    "DPS_GenerateUUID",
    "DPS_GetKeyStoreData",
    "DPS_GetLoop",
    "DPS_GetNodeData",
    "DPS_GetPublicationData",
    "DPS_GetSubscriptionData",
    "DPS_KeyStoreHandle",
    "DPS_MemoryKeyStoreHandle",
    "DPS_NodeAddrToString",
    "DPS_PublicationGetNumTopics",
    "DPS_PublicationGetTopic",
    "DPS_SetKeyStoreData",
    "DPS_SetNodeData",
    "DPS_SetPublicationData",
    "DPS_SetSubscriptionData",
    "DPS_SubscriptionGetNumTopics",
    "DPS_SubscriptionGetTopic",
    "DPS_UUID",
    "DPS_Key",
    "DPS_KeyId",
    "DPS_TRUE",
    "DPS_FALSE",
]

#
# Python
#

py_filler = TextWrapper()
py_parameter_filler = TextWrapper(initial_indent="    ", subsequent_indent="    ")
def py_escape(s):
    return s.replace('"', r'\"')

py_templates = {
    "returns": Template("""Returns
-------
$type
$description
"""),
    "enum_value": Template("""
%feature("docstring") $symbol "
$description
";
"""),
    "enum": Template("""
$values
"""),
    "parameter": Template("""$name : $type
$description
"""),
    "function": Template("""
%feature("docstring") $symbol "
$description

Parameters
----------
$parameters
$returns";
"""),
    "struct_member": Template("""
%feature("docstring") _$symbol::$name "
$description
";
"""),
    "struct": Template("""
%feature("docstring") _$symbol "
$description

Parameters
----------
$parameters
";
$properties
"""),
    "opaque_struct": Template(""),
    "callback": Template(""),
    "alias": Template(""),
    "variable": Template("""
%feature("docstring") $symbol "
$description
";
"""),
    "define": Template("""
%feature("docstring") $symbol "
$description
";
""")
}

def py_build_rename_dict(doxygen):
    global rename_pattern
    for section in doxygen.findall(".//sectiondef"):
        for memberdef in section:
            try:
                kind = memberdef.attrib["kind"]
                name = memberdef.find("name").text
                if kind == "enum":
                    rename_dict[name] = name.replace("DPS_", "")
                    for enumvalue in memberdef.findall("enumvalue"):
                        enumname = enumvalue.find("name").text
                        rename_dict[enumname] = enumname.replace("DPS_", "")
                elif kind == "typedef" or kind == "define":
                    rename_dict[name] = name.replace("DPS_", "")
                elif kind == "function" or kind == "variable":
                    s = name.replace("DPS_", "")
                    s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', s)
                    rename_dict[name] = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower()
            except KeyError:
                pass
    rename_dict["DPS_PublicationGetTopics"] = "publication_get_topics"
    rename_dict["DPS_SubscriptionGetTopics"] = "subscription_get_topics"
    rename_dict["TRUE"] = "True"
    rename_dict["FALSE"] = "False"
    rename_dict["NULL"] = "None"
    rename_pattern = re.compile(r'\b(' + '|'.join(rename_dict.keys()) + r')\b')

def py_type_text(text):
    text = text.replace("const", "")
    # Remove function pointer suffix if present
    if text.endswith("(*"):
        text = text[:-2]
    text = text.strip()

    if text == "int" or text == "int16_t" or text == "uint16_t" or text == "uint32_t" or text == "size_t":
        text = "int"
    elif text == "char *":
        text = "str"
    elif text == "uint8_t *":
        text = "list of int"
    elif text == "char **":
        text = "list of str"
    elif text == "struct sockaddr *":
        text = "tuple"
    elif text == "...":
        text = ""
    elif text == "void *":
        text = ""
    elif text == "DPS_KeyId *" or text == "DPS_KeyId":
        text = "list of int"
    else:
        text = text.strip(" *")

    return rename(text)

#
# JavaScript
#

js_filler = TextWrapper()
js_parameter_filler = TextWrapper()
def js_escape(s):
    return s

js_templates = {
    "returns": Template("\n @returns {$type} $description"),
    "enum_value": Template("\n    /** $description */\n    $name: $value,"),
    "enum": Template("""
/**
 $description

 @readonly
 @enum {number}
 */
var $name = {$values
}
"""),
    "parameter": Template("\n @param {$type} $name - $description"),
    "function": Template("""
/**
 $description
 $parameters
 $returns
 */
function $name () {
}
"""),
    "struct_member": Template("""
    /**
     $description
     @readonly
     @type {$type}
     */
    this.$name = {};
"""),
    "struct": Template("""
/**
 @class
 $description
 $parameters
 */
function $name () {
$properties
}
"""),
    "opaque_struct": Template("""
/**
 $description
 @typedef {Object} $name
 */
"""),
    "callback": Template("""
/**
 $description

 @callback $name
 $parameters
 $returns
 */
"""),
    "alias": Template("""
/**
 $description
 @typedef {$type} $name
 */
"""),
    "variable": Template("""
/**
 $description

 @type {$type}
 */
var $name = {
}
"""),
    "define": Template("""
/**
 $description

 @constant
 @default
 */
var $name = $value;
""")
}

def js_build_rename_dict(doxygen):
    global rename_pattern
    for section in doxygen.findall(".//sectiondef"):
        for memberdef in section:
            try:
                kind = memberdef.attrib["kind"]
                name = memberdef.find("name").text
                if kind == "enum":
                    rename_dict[name] = name.replace("DPS_", "")
                    for enumvalue in memberdef.findall("enumvalue"):
                        enumname = enumvalue.find("name").text
                        rename_dict[enumname] = enumname.replace("DPS_", "")
                elif kind == "typedef" or kind == "define":
                    rename_dict[name] = name.replace("DPS_", "")
                elif kind == "function" or kind == "variable":
                    rename_dict[name] = re.sub(r"DPS_(UUID|[A-Z])(.*)", lambda m: m.group(1).lower() + m.group(2), name)
            except KeyError:
                pass
    rename_dict["DPS_PublicationGetTopics"] = "publicationGetTopics"
    rename_dict["DPS_SubscriptionGetTopics"] = "subscriptionGetTopics"
    rename_dict["TRUE"] = "true"
    rename_dict["FALSE"] = "false"
    rename_dict["NULL"] = "null"
    rename_pattern = re.compile(r'\b(' + '|'.join(rename_dict.keys()) + r')\b')

def js_type_text(text):
    text = text.replace("const", "")
    # Remove function pointer suffix if present
    if text.endswith("(*"):
        text = text[:-2]
    text = text.strip()

    if text == "int" or text == "int16_t" or text == "uint16_t" or text == "uint32_t" or text == "size_t":
        text = "number"
    elif text == "char *":
        text = "string"
    elif text == "uint8_t *":
        text = "number[]"
    elif text == "char **":
        text = "string[]"
    elif text == "struct sockaddr *":
        text = "{address: string, family: string, port: number, flowinfo: number, scopeid: number}"
    elif text == "...":
        text = "...*"
    elif text == "void *":
        text = "*"
    elif text == "DPS_KeyId *" or text == "DPS_KeyId":
        text = "number[]"
    else:
        text = text.strip(" *")

    return rename(text)

def parameter_text(text):
    if text == "...":
        return "args"
    elif "@" in text:
        return None
    else:
        return text

#
# Common
#

rename_dict = {}

def rename(s):
    return rename_pattern.sub(lambda x: rename_dict[x.group()], s)

def description(elem, text_filler):
    if elem == None:
        return "";

    brief = elem.find("briefdescription")
    if brief != None:
        brieftext = text_filler.fill(rename("".join(brief.itertext()).strip()))
        detailed = elem.find("detaileddescription")
        if detailed != None:
            # Want to capture all the text up until the parameter or return doc
            detailedtext = ""
            para = ""
            for child in detailed.iter():
                if child.tag == "parameterlist" or (child.tag == "simplesect" and child.attrib.get("kind") == "return"):
                    break;
                if child.tag == "para":
                    detailedtext += "\n" + text_filler.fill(rename(para))
                    para = ""
                if child.text != None:
                    para += child.text
                if child.tail != None and not child.tail.isspace():
                    para += child.tail
            if detailedtext.isspace():
                detailedtext = ""
        return escape(brieftext + detailedtext)

    itemizedlist = elem.find(".//itemizedlist")
    if itemizedlist != None:
        items = []
        for listitem in itemizedlist.findall("listitem"):
            items.append("".join(listitem.itertext()).strip())
        return escape(text_filler.fill(rename("; ".join(items))))

    return escape(text_filler.fill(rename("".join(elem.itertext()))))

def type(elem):
    type = elem.find("type")
    if type == None:
        return None

    ref = type.find("ref")
    if ref != None:
        return type_text(ref.text)
    else:
        return type_text("".join(type.itertext()))

def parameter(elem):
    return parameter_text(elem.find("name").text)

def returns(elem):
    returntype = type(elem)
    if returntype != None and returntype != "void":
        desc = description(elem.find(".//simplesect[@kind='return']"), parameter_filler)
        return templates["returns"].substitute(type=returntype, description=desc)
    else:
        return ""

def enum(memberdef):
    value = -1;
    values = ""
    for enumvalue in memberdef.findall("enumvalue"):
        brief = description(enumvalue, filler)
        symbol = enumvalue.find("name").text
        try:
            initializer = enumvalue.find("initializer").text
            value = re.sub(r"= +(.*)", r"\1", initializer)
        except AttributeError:
            value = value + 1
        values += templates["enum_value"].substitute(symbol=symbol, description=brief, name=rename(symbol), value=value)
    brief = description(memberdef, filler)
    name = rename(memberdef.find("name").text)
    print >>outfile, templates["enum"].substitute(description=brief, name=name, values=values)

def skip_parameter(name):
    # Skip len parameters for arrays, not present in bindings
    return name == "len" or name == "n" or name == "numTopics"

def function(memberdef):
    parameters = ""
    for (param, parameteritem) in zip(memberdef.findall(".//param"), memberdef.findall(".//parameteritem")):
        paramtype = type(param)
        name = parameter_text(parameteritem.find(".//parametername").text)
        if skip_parameter(name):
            continue
        desc = description(parameteritem.find(".//parameterdescription"), parameter_filler)
        parameters += templates["parameter"].substitute(description=desc, name=name, type=paramtype)
    returnstext = rename(returns(memberdef))
    brief = description(memberdef, filler)
    symbol = memberdef.find("name").text
    print >>outfile, templates["function"].substitute(symbol=symbol, description=brief, name=rename(symbol), parameters=parameters, returns=returnstext)

def struct_members(symbol, compound_xml):
    members = ""
    for memberdef in compound_xml.findall(".//memberdef"):
        membertype = type(memberdef)
        name = parameter(memberdef)
        if name == None:
            continue
        desc = description(memberdef, filler)
        members += templates["struct_member"].substitute(symbol=symbol, description=desc, name=name, type=membertype)
    return members

def struct(elem):
    brief = description(elem, filler)
    filename = elem.find("type/ref").attrib["refid"] + ".xml"
    compound_xml = ET.parse(os.path.join(indir, filename))
    parameters = ""
    # Sort by source line number since members are not listed in order in the XML
    for param in sorted(compound_xml.findall(".//memberdef"), key=lambda elem: elem.find("location").attrib["line"]):
        paramtype = type(param)
        paramname = parameter(param)
        if skip_parameter(paramname):
            continue
        desc = description(param, parameter_filler)
        parameters += templates["parameter"].substitute(description=desc, name=paramname, type=paramtype)
    symbol = elem.find("name").text
    properties = struct_members(symbol, compound_xml)
    if symbol == "DPS_KeySymmetric" or symbol == "DPS_KeyEC" or symbol == "DPS_KeyCert":
        # The bindings add a type member to Key structs
        properties += templates["struct_member"].substitute(symbol=symbol, description=filler.fill("Type of key"), type="KeyType", name="type")
    print >>outfile, templates["struct"].substitute(symbol=symbol, description=brief, parameters=parameters, name=rename(symbol), properties=properties)

def opaque_struct(elem):
    brief = description(elem, filler)
    name = rename(elem.find("name").text)
    print >>outfile, templates["opaque_struct"].substitute(description=brief, name=name)

def callback(elem):
    argsstring = elem.find("argsstring").text.strip("()").split(", ")
    parameters = ""
    for (param, parameteritem) in zip(argsstring, elem.findall(".//parameteritem")):
        name = parameteritem.find(".//parametername").text
        if skip_parameter(name):
            continue
        paramtype = type_text(param.replace(name, ""))
        desc = description(parameteritem.find(".//parameterdescription"), parameter_filler)
        parameters += templates["parameter"].substitute(type=paramtype, name=name, description=desc)

    brief = description(elem, filler)
    name = rename(elem.find("name").text)
    returnstext = rename(returns(elem))
    print >>outfile, templates["callback"].substitute(description=brief, name=name, parameters=parameters, returns=returnstext)

def alias(elem):
    brief = description(elem, filler)
    typename = type(elem)
    name = rename(elem.find("name").text)
    print >>outfile, templates["alias"].substitute(description=brief, type=typename, name=name)

def typedef(memberdef):
    name = rename(memberdef.find("name").text)
    typename = "".join(memberdef.find("type").itertext()).strip()
    if typename.startswith("struct"):
        ref = memberdef.find("type/ref")
        if ref != None:
            struct(memberdef)
        else:
            opaque_struct(memberdef)
    elif typename.endswith("(*"):
        callback(memberdef)
    else:
        alias(memberdef)

def variable(memberdef):
    brief = description(memberdef, filler)
    symbol = memberdef.find("name").text
    typename =  type(memberdef)
    print >>outfile, templates["variable"].substitute(symbol=symbol, description=brief, type=typename, name=rename(symbol))

def define(memberdef):
    # Ignore macros
    if memberdef.find("param") != None:
        return
    brief = description(memberdef, filler)
    symbol = memberdef.find("name").text
    initializer = memberdef.find("initializer").text
    print >>outfile, templates["define"].substitute(symbol=symbol, description=brief, name=rename(symbol), value=initializer)

def doc(doxygen):
    for section in doxygen.findall(".//sectiondef"):
        for memberdef in section:
            name = memberdef.find("name")
            if name != None and name.text in ignore:
                continue
            try:
                kind = memberdef.attrib["kind"]
                if kind == "enum":
                    enum(memberdef)
                elif kind == "function":
                    function(memberdef)
                elif kind == "typedef":
                    typedef(memberdef)
                elif kind == "variable":
                    variable(memberdef)
                elif kind == "define":
                    define(memberdef)
            except KeyError:
                pass

def parse(index, parser):
    for compound in index.findall("*[@kind='file']"):
        filename = compound.attrib["refid"] + ".xml"
        compound_xml = ET.parse(os.path.join(indir, filename))
        doxygen = compound_xml.getroot()
        name = doxygen.find(".//compoundname").text
        if name == "registration.h":
            continue
        parser(doxygen)

def generate(language, xml, out):
    global templates, type_text, build_rename_dict, filler, parameter_filler, escape
    global indir, outfile

    if out == None:
        outfile = sys.stdout
    else:
        outfile = open(out, "w")

    if language == "py":
        templates = py_templates
        type_text = py_type_text
        build_rename_dict = py_build_rename_dict
        filler = py_filler
        parameter_filler = py_parameter_filler
        escape = py_escape
    elif language == "js":
        templates = js_templates
        type_text = js_type_text
        build_rename_dict = js_build_rename_dict
        filler = js_filler
        parameter_filler = js_parameter_filler
        escape = js_escape

    indir = os.path.dirname(xml)
    index_xml = ET.parse(xml)
    index = index_xml.getroot()
    # Renaming depends on the type of symbol, so do the generation in two passes
    parse(index, build_rename_dict)
    parse(index, doc)

    # Bindings specific functions, overloads
    parameters = templates["parameter"].substitute(description=parameter_filler.fill("The publication"),
                                                   name="pub",
                                                   type=type_text("const DPS_Publication *"))
    returns = rename(templates["returns"].substitute(type=type_text("const char **"),
                                                     description=parameter_filler.fill("The topic strings or NULL if the publication is invalid.")))
    print >>outfile, templates["function"].substitute(symbol="DPS_PublicationGetTopics",
                                           description=filler.fill("Get topics for a publication"),
                                           name=rename("DPS_PublicationGetTopics"),
                                           parameters=parameters,
                                           returns=returns)

    parameters = templates["parameter"].substitute(description=parameter_filler.fill("The subscription"),
                                                   name="sub",
                                                   type=type_text("const DPS_Subscription *"))
    returns = rename(templates["returns"].substitute(type=type_text("const char **"),
                                                     description=parameter_filler.fill("The topic strings or NULL if the subscription is invalid.")))
    print >>outfile, templates["function"].substitute(symbol="DPS_SubscriptionGetTopics",
                                           description=filler.fill("Get topics for an active subscription"),
                                           name=rename("DPS_SubscriptionGetTopics"),
                                           parameters=parameters,
                                           returns=returns)

    parameters = templates["parameter"].substitute(description=escape(parameter_filler.fill(rename("The separator characters to use for topic matching, if NULL defaults to \"/\""))),
                                                   name="separators",
                                                   type=type_text("const char *"))
    if language == "py":
        paramtext = "KeyStore or MemoryKeyStore"
    elif language == "js":
        paramtext = "KeyStore|MemoryKeyStore"
    parameters += templates["parameter"].substitute(description=parameter_filler.fill(rename("The key store to use for this node")),
                                                                                      name="keyStore",
                                                                                      type=paramtext)
    parameters += templates["parameter"].substitute(description=parameter_filler.fill(rename("The key identifier of this node")),
                                                                                      name="keyId",
                                                                                      type=type_text("const uint8_t *"))
    returns = rename(templates["returns"].substitute(type=type_text("DPS_Node *"),
                                                     description=parameter_filler.fill(rename("The uninitialized node or NULL if there were no resources for the node."))))
    print >>outfile, templates["function"].substitute(symbol="DPS_CreateNode",
                                           description=filler.fill("Allocates space for a local DPS node."),
                                           name=rename("DPS_CreateNode"),
                                           parameters=parameters,
                                           returns=returns)

    print >>outfile, templates["opaque_struct"].substitute(description=filler.fill("Type definition for a UUID"),
                                                name=rename("DPS_UUID"))

    returns = rename(templates["returns"].substitute(type=type_text("DPS_UUID *"),
                                                     description=parameter_filler.fill("The generated UUID.")))
    print >>outfile, templates["function"].substitute(symbol="DPS_GenerateUUID",
                                           description=filler.fill("Non secure generation of a random UUID."),
                                           name=rename("DPS_GenerateUUID"),
                                           parameters="",
                                           returns=returns)

    if out != None:
        outfile.close()

if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("language", choices=("py", "js"), default="py",
                        help="Generate docs for Python or JavaScript")
    parser.add_argument("xml",
                        help="Path to Doxygen index.xml")
    args = parser.parse_args()

    generate(args.language, args.xml, None)
