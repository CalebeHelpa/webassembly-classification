

try:
    from os import listdir
    from os.path import isfile, join
    import sys
    import csv

    import warnings
    warnings.simplefilter(action='ignore', category=FutureWarning)

except Exception as e:
    print('Unmet dependency:', e)
    sys.exit(1)

class DwarfExtractor():

    def extract_attribute_type(self, attribute):
        start_index = attribute.index('"')
        # Encontra o índice do último parêntese de fechamento
        end_index = attribute.rindex('"')
        # Extrai a substring entre esses índices
        value = attribute[start_index + 1:end_index]
        return value

    def extract_language(self, attribute):
        start_index = attribute.index('(')
        # Encontra o índice do último parêntese de fechamento
        end_index = attribute.index(')')
        # Extrai a substring entre os parênteses
        value = attribute[start_index + 1:end_index]
        return value


    def main(self):
    
        field_names = ['id', 'malicioso', 'lines', 'language', 'dw_tag_subprogram', 'dw_tag_typedef', 'pointer_type', 'address_type', 'dw_tag_formal_parameter', 'dw_tag_variable',
                       'dw_tag_member', 'dw_tag_label', 'dw_tag_gnu_call_site', 'dw_at_gnu_all_call_sites', 'dw_tag_inlined_subroutine', 'dw_at_external', 'dw_at_call_file',
                       'int_type', 'uint_type', 'string_type', 'fp_type', 'bool_type','dw_tag_variable_int', 'dw_tag_variable_uint', 'dw_tag_variable_string', 'dw_tag_variable_fp',
                       'dw_tag_variable_bool', 'dw_tag_formal_parameter_int', 'dw_tag_formal_parameter_uint', 'dw_tag_formal_parameter_string', 'dw_tag_formal_parameter_fp', 
                       'dw_tag_formal_parameter_bool','dw_tag_enumerator', 'dw_access_public', 'dw_access_private', 'dw_access_protected']
    
        unsigned_type = ["unsigned int", "uint8_t", "uint64_t", "uint32_t", "long unsigned int", "long long unsigned int"]
        
        signedint_type = ["int", "long int", "long long int", "wint_t"]
        
        charPointer_type = ["const char*", "restrict const char*", "char*", "restrict const wchar_t*", "wchar_t*", "const wchar_t*", "restrict char*",
                     "basic_string<char, std::char_traits<char>, std::allocator<char> >*", "restrict wchar_t*", "restrict wchar_t**"]
        
        filePointer_type = ["FILE*", "restrict FILE*", "FileMetaData*", "FileMetaData**"]

        boolean_type = ["bool", "boolean"]

        idFile = 0

        lines = 0
        dw_tag_subprogram = 0
        dw_tag_typedef = 0
        pointer_type = 0
        address_type = 0
        dw_tag_formal_parameter = 0
        dw_tag_variable = 0
        dw_tag_member = 0
        dw_tag_label = 0
        dw_tag_gnu_call_site = 0
        dw_at_gnu_all_call_sites = 0
        dw_tag_inlined_subroutine = 0
        dw_at_external = 0
        dw_at_call_file = 0

        dw_tag_enumerator = 0

        int_type = 0
        uint_type = 0
        string_type = 0
        fp_type = 0
        bool_type = 0

        dw_tag_variable_int = 0
        dw_tag_variable_uint = 0
        dw_tag_variable_string = 0
        dw_tag_variable_fp = 0
        dw_tag_variable_bool = 0

        dw_tag_formal_parameter_int = 0
        dw_tag_formal_parameter_uint = 0
        dw_tag_formal_parameter_string = 0
        dw_tag_formal_parameter_fp = 0
        dw_tag_formal_parameter_bool = 0

        dw_access_public = 0
        dw_access_private = 0
        dw_access_protected = 0

        variable_flag = 0
        formal_parameter_flag = 0

        path = "./data/normal-dwarf/" # PATH TO NORMAL FILES
        # path = "./data/anomaly-dwarf/" # PATH TO ANOMALY FILES
        
        files = [f for f in listdir(path) if isfile(join(path, f))]

        if "normal" in path:
            malicioso = 0
        else:
            malicioso = 1
    
        for i in files:
            arq = path + i
            
            with open(arq, "r", encoding='utf8') as arquivo:
                
                for frase in arquivo.readlines():
                    if "DW_TAG_subprogram" in frase:
                        dw_tag_subprogram += 1
                    
                    if "DW_TAG_typedef" in frase:
                        dw_tag_typedef += 1
                    
                    if "DW_TAG_formal_parameter" in frase:
                        dw_tag_formal_parameter += 1
                        formal_parameter_flag = 1
                    
                    if "DW_TAG_variable" in frase:
                        dw_tag_variable += 1
                        variable_flag = 1
                    
                    if "DW_TAG_member" in frase:
                        dw_tag_member += 1
                    
                    if "DW_TAG_label" in frase:
                        dw_tag_label += 1
    
                    if "DW_TAG_GNU_call_site" in frase:
                        dw_tag_gnu_call_site += 1

                    if "DW_AT_GNU_all_call_sites" in frase:
                        dw_at_gnu_all_call_sites += 1
    
                    if "DW_TAG_inlined_subroutine" in frase:
                        dw_tag_inlined_subroutine += 1                
    
                    if "DW_AT_external" in frase:
                        dw_at_external += 1

                    if "DW_AT_call_file" in frase:
                        dw_at_call_file += 1

                    if "DW_AT_type" in frase:
                        value = self.extract_attribute_type(frase)
                
                        if value in signedint_type:
                            int_type += 1
                            
                            if variable_flag == 1 :
                                dw_tag_variable_int += 1
                                variable_flag = 0
                            
                            if formal_parameter_flag == 1:
                                dw_tag_formal_parameter_int += 1
                                formal_parameter_flag = 0

                        if value in unsigned_type:
                            uint_type += 1

                            if variable_flag == 1 :
                                dw_tag_variable_uint += 1
                                variable_flag = 0
                            
                            if formal_parameter_flag == 1:
                                dw_tag_formal_parameter_uint += 1
                                formal_parameter_flag = 0
                        
                        if value in charPointer_type:
                            string_type += 1
                        
                            if variable_flag == 1 :
                                dw_tag_variable_string += 1
                                variable_flag = 0
                            
                            if formal_parameter_flag == 1:
                                dw_tag_formal_parameter_string += 1
                                formal_parameter_flag = 0

                        if value in filePointer_type:
                            fp_type += 1

                            if variable_flag == 1 :
                                dw_tag_variable_fp += 1
                                variable_flag = 0
                            
                            if formal_parameter_flag == 1:
                                dw_tag_formal_parameter_fp += 1
                                formal_parameter_flag = 0
                        
                        if value in boolean_type:
                            bool_type += 1

                            if variable_flag == 1 :
                                dw_tag_variable_bool += 1
                                variable_flag = 0
                            
                            if formal_parameter_flag == 1:
                                dw_tag_formal_parameter_bool += 1
                                formal_parameter_flag = 0

                    if "DW_AT_language" in frase:
                        language = self.extract_language(frase)

                    if "DW_TAG_enumerator" in frase:
                        dw_tag_enumerator += 1

                    if "DW_ACCESS_public" in frase:
                        dw_access_public += 1

                    if "DW_ACCESS_private" in frase:
                        dw_access_private += 1

                    if "DW_ACCESS_protected" in frase:
                        dw_access_protected += 1

                    lines += 1


                dict = {"id": idFile, "malicioso": malicioso, "lines": lines, "language": language,"dw_tag_subprogram": dw_tag_subprogram, "dw_tag_typedef": dw_tag_typedef,
                        "pointer_type": pointer_type, "address_type": address_type, "dw_tag_formal_parameter": dw_tag_formal_parameter , "dw_tag_variable": dw_tag_variable,
                        "dw_tag_member": dw_tag_member, "dw_tag_label": dw_tag_label, "dw_tag_gnu_call_site": dw_tag_gnu_call_site, "dw_at_gnu_all_call_sites": dw_at_gnu_all_call_sites,
                        "dw_tag_inlined_subroutine": dw_tag_inlined_subroutine, "dw_at_external": dw_at_external, "dw_at_call_file": dw_at_call_file,
                        "int_type": int_type, "uint_type": uint_type, "string_type": uint_type, "fp_type": fp_type, "bool_type":bool_type,"dw_tag_variable_int":dw_tag_variable_int,
                        "dw_tag_variable_uint": dw_tag_variable_uint, "dw_tag_variable_string": dw_tag_variable_string, "dw_tag_variable_fp": dw_tag_variable_fp, "dw_tag_variable_bool": dw_tag_variable_bool,
                        "dw_tag_formal_parameter_int": dw_tag_formal_parameter_int, "dw_tag_formal_parameter_uint":dw_tag_formal_parameter_uint,
                        "dw_tag_formal_parameter_string": dw_tag_formal_parameter_string, "dw_tag_formal_parameter_fp": dw_tag_formal_parameter_fp, "dw_tag_formal_parameter_bool":dw_tag_formal_parameter_bool,
                        "dw_tag_enumerator": dw_tag_enumerator, "dw_access_public":dw_access_public, "dw_access_private":dw_access_private, "dw_access_protected":dw_access_protected }
    
                with open('./webassembly_dwarf_dataset_test.csv', 'a') as csv_file:
                    dict_object = csv.DictWriter(csv_file, fieldnames=field_names) 
    
                    dict_object.writerow(dict)
    
                idFile += 1

                lines = 0
                dw_tag_subprogram = 0
                dw_tag_typedef = 0
                pointer_type = 0
                address_type = 0
                dw_tag_formal_parameter = 0
                dw_tag_variable = 0
                dw_tag_member = 0
                dw_tag_label = 0
                dw_tag_gnu_call_site = 0
                dw_at_gnu_all_call_sites = 0
                dw_tag_inlined_subroutine = 0
                dw_at_external = 0
                dw_at_call_file = 0

                int_type = 0
                uint_type = 0
                string_type = 0
                fp_type = 0
                bool_type = 0

                dw_tag_variable_int = 0
                dw_tag_variable_uint = 0
                dw_tag_variable_string = 0
                dw_tag_variable_fp = 0
                dw_tag_variable_bool = 0

                dw_tag_formal_parameter_int = 0
                dw_tag_formal_parameter_uint = 0
                dw_tag_formal_parameter_string = 0
                dw_tag_formal_parameter_fp = 0
                dw_tag_formal_parameter_bool = 0

                dw_access_public = 0
                dw_access_private = 0
                dw_access_protected = 0

                variable_flag = 0
                formal_parameter_flag = 0
    
if __name__ == '__main__':

    try:
        worker = DwarfExtractor()
        worker.main()
    except KeyboardInterrupt as e:
        print('Exit using ctrl^C')
     