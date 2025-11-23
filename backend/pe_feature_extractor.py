"""
PE File Feature Extractor for Malware Detection
Extracts features from Windows PE files compatible with XGBoost model
"""

import pefile
import hashlib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional
import warnings
warnings.filterwarnings('ignore')


class PEFeatureExtractor:
    """Extract features from PE files for malware classification"""
    
    def __init__(self, model_features_path: Optional[Path] = None, expected_features: Optional[List[str]] = None):
        """
        Initialize the PE feature extractor
        
        Args:
            model_features_path: Path to the saved top_features.joblib file
            expected_features: List of feature names expected by the model (to filter DLLs/APIs)
        """
        self.model_features = None
        self.expected_features = expected_features
        
        if model_features_path:
            import joblib
            self.model_features = joblib.load(model_features_path)
        
        # If expected features provided, extract DLL and API lists from them
        if expected_features:
            self.dll_list = [f for f in expected_features if f.endswith('.dll') or f.endswith('.drv') or f.endswith('.cpl') or f.endswith('.ocx')]
            self.api_functions = [f for f in expected_features if not f.endswith(('.dll', '.drv', '.cpl', '.ocx')) 
                                 and f not in ['SHA256', 'Type', 'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 
                                               'e_cparhdr', 'e_minalloc', 'e_maxalloc', 'e_ss', 'e_sp', 
                                               'e_csum', 'e_ip', 'e_cs', 'e_lfarlc', 'e_ovno', 'e_oemid', 
                                               'e_oeminfo', 'e_lfanew', 'Machine', 'NumberOfSections',
                                               'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols',
                                               'SizeOfOptionalHeader', 'Characteristics']
                                 and not any(f.startswith(prefix) for prefix in 
                                           ['text_', 'data_', 'rdata_', 'bss_', 'idata_', 'edata_',
                                            'rsrc_', 'reloc_', 'tls_', 'pdata_', 'Magic', 'MajorLinker',
                                            'MinorLinker', 'SizeOf', 'AddressOf', 'BaseOf', 'ImageBase',
                                            'Section', 'File', 'Major', 'Minor', 'Reserved', 'CheckSum',
                                            'Subsystem', 'DllCharacteristics', 'LoaderFlags', 'NumberOf'])]
        else:
            # Fallback to default lists (will be filtered later anyway)
            self.dll_list = []
            self.api_functions = []
        
    def calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def extract_dos_header(self, pe: pefile.PE) -> Dict:
        """Extract DOS header features"""
        dos = pe.DOS_HEADER
        return {
            'e_magic': dos.e_magic,
            'e_cblp': dos.e_cblp,
            'e_cp': dos.e_cp,
            'e_crlc': dos.e_crlc,
            'e_cparhdr': dos.e_cparhdr,
            'e_minalloc': dos.e_minalloc,
            'e_maxalloc': dos.e_maxalloc,
            'e_ss': dos.e_ss,
            'e_sp': dos.e_sp,
            'e_csum': dos.e_csum,
            'e_ip': dos.e_ip,
            'e_cs': dos.e_cs,
            'e_lfarlc': dos.e_lfarlc,
            'e_ovno': dos.e_ovno,
            'e_oemid': dos.e_oemid,
            'e_oeminfo': dos.e_oeminfo,
            'e_lfanew': dos.e_lfanew
        }
    
    def extract_file_header(self, pe: pefile.PE) -> Dict:
        """Extract FILE header features"""
        fh = pe.FILE_HEADER
        return {
            'Machine': fh.Machine,
            'NumberOfSections': fh.NumberOfSections,
            'TimeDateStamp': fh.TimeDateStamp,
            'PointerToSymbolTable': fh.PointerToSymbolTable,
            'NumberOfSymbols': fh.NumberOfSymbols,
            'SizeOfOptionalHeader': fh.SizeOfOptionalHeader,
            'Characteristics': fh.Characteristics
        }
    
    def extract_optional_header(self, pe: pefile.PE) -> Dict:
        """Extract OPTIONAL header features"""
        oh = pe.OPTIONAL_HEADER
        features = {
            'Magic': oh.Magic,
            'MajorLinkerVersion': oh.MajorLinkerVersion,
            'MinorLinkerVersion': oh.MinorLinkerVersion,
            'SizeOfCode': oh.SizeOfCode,
            'SizeOfInitializedData': oh.SizeOfInitializedData,
            'SizeOfUninitializedData': oh.SizeOfUninitializedData,
            'AddressOfEntryPoint': oh.AddressOfEntryPoint,
            'BaseOfCode': oh.BaseOfCode,
            'ImageBase': oh.ImageBase,
            'SectionAlignment': oh.SectionAlignment,
            'FileAlignment': oh.FileAlignment,
            'MajorOperatingSystemVersion': oh.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': oh.MinorOperatingSystemVersion,
            'MajorImageVersion': oh.MajorImageVersion,
            'MinorImageVersion': oh.MinorImageVersion,
            'MajorSubsystemVersion': oh.MajorSubsystemVersion,
            'MinorSubsystemVersion': oh.MinorSubsystemVersion,
            'Reserved1': getattr(oh, 'Reserved1', 0),
            'SizeOfImage': oh.SizeOfImage,
            'SizeOfHeaders': oh.SizeOfHeaders,
            'CheckSum': oh.CheckSum,
            'Subsystem': oh.Subsystem,
            'DllCharacteristics': oh.DllCharacteristics,
            'SizeOfStackReserve': oh.SizeOfStackReserve,
            'SizeOfHeapReserve': oh.SizeOfHeapReserve,
            'SizeOfHeapCommit': oh.SizeOfHeapCommit,
            'LoaderFlags': oh.LoaderFlags,
            'NumberOfRvaAndSizes': oh.NumberOfRvaAndSizes
        }
        return features
    
    def extract_sections(self, pe: pefile.PE) -> Dict:
        """Extract section features"""
        section_names = ['.text', '.data', '.rdata', '.bss', '.idata', 
                        '.edata', '.rsrc', '.reloc', '.tls', '.pdata']
        
        features = {}
        for section_name in section_names:
            prefix = section_name[1:]  # Remove leading dot
            # Initialize all features to 0
            features[f'{prefix}_Misc_VirtualSize'] = 0
            features[f'{prefix}_VirtualAddress'] = 0
            features[f'{prefix}_SizeOfRawData'] = 0
            features[f'{prefix}_PointerToRawData'] = 0
            features[f'{prefix}_PointerToRelocations'] = 0
            features[f'{prefix}_PointerToLinenumbers'] = 0
            features[f'{prefix}_NumberOfRelocations'] = 0
            features[f'{prefix}_NumberOfLinenumbers'] = 0
            features[f'{prefix}_Characteristics'] = 0
        
        # Fill in actual section data
        for section in pe.sections:
            try:
                name = section.Name.decode().strip('\x00').lower()
                if name in section_names:
                    prefix = name[1:]
                    features[f'{prefix}_Misc_VirtualSize'] = section.Misc_VirtualSize
                    features[f'{prefix}_VirtualAddress'] = section.VirtualAddress
                    features[f'{prefix}_SizeOfRawData'] = section.SizeOfRawData
                    features[f'{prefix}_PointerToRawData'] = section.PointerToRawData
                    features[f'{prefix}_PointerToRelocations'] = section.PointerToRelocations
                    features[f'{prefix}_PointerToLinenumbers'] = section.PointerToLinenumbers
                    features[f'{prefix}_NumberOfRelocations'] = section.NumberOfRelocations
                    features[f'{prefix}_NumberOfLinenumbers'] = section.NumberOfLinenumbers
                    features[f'{prefix}_Characteristics'] = section.Characteristics
            except:
                continue
        
        return features
    
    def extract_imports(self, pe: pefile.PE) -> Dict:
        """Extract imported DLLs and API functions"""
        # Initialize all DLLs to 0
        dll_features = {dll: 0 for dll in self.dll_list}
        # Initialize all API functions to 0
        api_features = {func: 0 for func in self.api_functions}
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return {**dll_features, **api_features}
        
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower()
                
                # Mark DLL as imported
                if dll_name in dll_features:
                    dll_features[dll_name] = 1
                
                # Mark imported functions
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode().lower()
                        if func_name in api_features:
                            api_features[func_name] = 1
        except:
            pass
        
        return {**dll_features, **api_features}
    
    def extract_features_from_file(self, file_path: Path, file_type: str = "unknown") -> Dict:
        """
        Extract all features from a PE file
        
        Args:
            file_path: Path to the PE file
            file_type: Optional malware type label
            
        Returns:
            Dictionary of all features
        """
        features = {}
        
        try:
            # Calculate SHA256
            features['SHA256'] = self.calculate_sha256(file_path)
            features['Type'] = file_type
            
            # Parse PE file
            pe = pefile.PE(str(file_path))
            
            # Extract all feature groups
            features.update(self.extract_dos_header(pe))
            features.update(self.extract_file_header(pe))
            features.update(self.extract_optional_header(pe))
            features.update(self.extract_sections(pe))
            features.update(self.extract_imports(pe))
            
            pe.close()
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return None
        
        return features
    
    def extract_features_batch(self, file_paths: List[Path], 
                               labels: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Extract features from multiple PE files
        
        Args:
            file_paths: List of paths to PE files
            labels: Optional list of malware type labels
            
        Returns:
            DataFrame with all features
        """
        if labels is None:
            labels = ["unknown"] * len(file_paths)
        
        all_features = []
        for file_path, label in zip(file_paths, labels):
            print(f"Processing: {file_path.name}")
            features = self.extract_features_from_file(file_path, label)
            if features:
                all_features.append(features)
        
        df = pd.DataFrame(all_features)
        
        # Reorder columns to match training data format
        # First: SHA256, Type, then all other features
        cols = ['SHA256', 'Type'] + [col for col in df.columns if col not in ['SHA256', 'Type']]
        df = df[cols]
        
        # Fill missing values with 0
        df = df.fillna(0)
        
        return df
    
    def prepare_for_prediction(self, df: pd.DataFrame, 
                              scaler_header, scaler_section,
                              expected_features=None) -> pd.DataFrame:
        """
        Prepare extracted features for model prediction
        
        Args:
            df: DataFrame with extracted features
            scaler_header: Fitted StandardScaler for header features
            scaler_section: Fitted StandardScaler for section features
            expected_features: List of features expected by the model (optional)
            
        Returns:
            Processed DataFrame ready for prediction
        """
        # If expected features are provided, filter DataFrame FIRST to avoid scaler issues
        if expected_features is not None:
            # Only keep columns that are in expected features OR are metadata
            valid_cols = ['Type', 'SHA256'] + [col for col in df.columns if col in expected_features]
            df = df[[col for col in valid_cols if col in df.columns]]
            
            # Add any missing expected features with value 0
            for col in expected_features:
                if col not in df.columns:
                    df[col] = 0
        
        # Separate into feature groups
        header_cols = [col for col in df.columns if col not in ['Type', 'SHA256'] 
                      and not any(col.startswith(s) for s in ['text_', 'data_', 'rdata_', 
                                                                'bss_', 'idata_', 'edata_', 
                                                                'rsrc_', 'reloc_', 'tls_', 'pdata_'])]
        
        section_cols = [col for col in df.columns if any(col.startswith(s) 
                       for s in ['text_', 'data_', 'rdata_', 'bss_', 'idata_', 
                                'edata_', 'rsrc_', 'reloc_', 'tls_', 'pdata_'])]
        
        # Apply standardization (only to numeric features, not DLLs/APIs which are binary)
        dll_api_cols = [col for col in df.columns if col.endswith(('.dll', '.drv', '.cpl', '.ocx')) or 
                       col in self.api_functions]
        
        numeric_header_cols = [col for col in header_cols if col not in dll_api_cols]
        
        if numeric_header_cols:
            df[numeric_header_cols] = scaler_header.transform(df[numeric_header_cols])
        
        if section_cols:
            df[section_cols] = scaler_section.transform(df[section_cols])
        
        return df


def main():
    """Example usage"""
    import joblib
    
    # Setup paths
    base_dir = Path('.')
    models_dir = base_dir / 'saved_models' / 'xgboost'
    
    # Initialize extractor
    extractor = PEFeatureExtractor()
    
    # Example: Extract features from a single PE file
    pe_file = Path("path/to/suspicious.exe")
    
    if pe_file.exists():
        print(f"Extracting features from: {pe_file}")
        features = extractor.extract_features_from_file(pe_file, file_type="unknown")
        
        if features:
            print(f"\nExtracted {len(features)} features")
            print(f"SHA256: {features['SHA256']}")
            print(f"Sample features: {list(features.keys())[:10]}")
    
    # Example: Batch extraction
    pe_files = list(Path("path/to/pe/files").glob("*.exe"))
    if pe_files:
        print(f"\nProcessing {len(pe_files)} PE files...")
        df = extractor.extract_features_batch(pe_files)
        print(f"\nExtracted features shape: {df.shape}")
        print(df.head())
        
        # Save to CSV
        output_path = base_dir / 'extracted_pe_features.csv'
        df.to_csv(output_path, index=False)
        print(f"\nFeatures saved to: {output_path}")


if __name__ == "__main__":
    main()
