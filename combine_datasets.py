"""
Combine multiple phishing datasets into a single comprehensive dataset.
Supports various CSV formats and combines them into phishing_data.csv
"""

import pandas as pd
import numpy as np
import os
import glob
from urllib.parse import urlparse


def is_valid_url(url):
    """Check if a string is a valid URL."""
    if not isinstance(url, str) or pd.isna(url):
        return False
    parsed = urlparse(str(url))
    return bool(parsed.netloc)


def load_and_process_dataset(file_path, url_column=None, label_column=None, label_mapping=None):
    """
    Load and process a single dataset file.
    
    Args:
        file_path (str): Path to the CSV file
        url_column (str): Name of the URL column (auto-detect if None)
        label_column (str): Name of the label column (auto-detect if None)
        label_mapping (dict): Mapping from dataset labels to standard labels
        
    Returns:
        pd.DataFrame: Processed dataframe with 'url' and 'label' columns
    """
    try:
        df = pd.read_csv(file_path)
        print(f"Loaded {file_path}: {len(df)} rows, columns: {df.columns.tolist()}")
        
        # Auto-detect URL column
        if url_column is None:
            url_candidates = ['url', 'URL', 'Url', 'link', 'Link', 'website', 'Website', 
                            'domain', 'Domain', 'uri', 'URI', 'address', 'Address']
            for col in df.columns:
                if col.lower() in [c.lower() for c in url_candidates]:
                    url_column = col
                    break
        
        # Auto-detect label column
        if label_column is None:
            label_candidates = ['label', 'Label', 'type', 'Type', 'class', 'Class', 
                               'result', 'Result', 'status', 'Status', 'phishing', 
                               'malicious', 'legitimate', 'target']
            for col in df.columns:
                if col.lower() in [c.lower() for c in label_candidates]:
                    label_column = col
                    break
        
        if url_column is None:
            print(f"Warning: Could not find URL column in {file_path}")
            return None
        
        if label_column is None:
            print(f"Warning: Could not find label column in {file_path}")
            return None
        
        # Extract and clean URLs
        df['url'] = df[url_column].astype(str)
        df = df[df['url'].apply(is_valid_url)]
        
        # Map labels to standard format
        if label_mapping:
            df['label'] = df[label_column].map(label_mapping)
        else:
            df['label'] = df[label_column].astype(str).str.lower()
            # Standardize labels
            df['label'] = df['label'].replace({
                '0': 'legitimate',
                '1': 'phishing',
                'benign': 'legitimate',
                'malicious': 'phishing',
                'bad': 'phishing',
                'good': 'legitimate',
                'safe': 'legitimate',
                'unsafe': 'phishing',
                'false': 'legitimate',
                'true': 'phishing'
            })
        
        # Keep only url and label columns
        result = df[['url', 'label']].copy()
        
        # Remove duplicates
        result = result.drop_duplicates(subset=['url'])
        
        print(f"Processed {file_path}: {len(result)} valid URLs")
        return result
        
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return None


def generate_synthetic_data(num_samples=10000):
    """
    Generate synthetic phishing and legitimate URLs for training.
    Used when real datasets are not available.
    """
    np.random.seed(42)
    
    legitimate_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'apple.com',
        'microsoft.com', 'netflix.com', 'paypal.com', 'ebay.com', 'reddit.com',
        'pinterest.com', 'tumblr.com', 'wordpress.com', 'blogspot.com', 'dropbox.com'
    ]
    
    phishing_patterns = [
        'verify-{}-account.com',
        '{}-secure-login.tk',
        '{}-update-required.ml',
        '{}-confirm-identity.ga',
        '{}-billing-info.cf',
        'login-{}-secure.gq',
        '{}-account-verify.xyz',
        '{}-payment-update.top',
        'secure-{}-portal.buzz',
        '{}-authentication-required.com'
    ]
    
    urls = []
    labels = []
    
    # Generate legitimate URLs (50%)
    for _ in range(num_samples // 2):
        domain = np.random.choice(legitimate_domains)
        path = np.random.choice(['', '/login', '/signup', '/about', '/contact', 
                               '/products', '/services', f'/page{np.random.randint(1, 100)}'])
        protocol = 'https' if np.random.random() > 0.3 else 'http'
        url = f"{protocol}://www.{domain}{path}"
        urls.append(url)
        labels.append('legitimate')
    
    # Generate phishing URLs (50%)
    for _ in range(num_samples // 2):
        brand = np.random.choice(['paypal', 'apple', 'microsoft', 'google', 'facebook',
                                 'amazon', 'netflix', 'bank', 'chase', 'wellsfargo'])
        pattern = np.random.choice(phishing_patterns)
        domain = pattern.format(brand)
        path = np.random.choice(['/login', '/verify', '/update', '/confirm', 
                               '/secure', '/auth', '/billing'])
        
        # Add some variation
        if np.random.random() > 0.5:
            domain = domain.replace('-', np.random.choice(['_', '', '--']))
        
        protocol = 'https' if np.random.random() > 0.7 else 'http'
        
        # Sometimes use IP address
        if np.random.random() > 0.8:
            ip = f"{np.random.randint(1, 256)}.{np.random.randint(1, 256)}.{np.random.randint(1, 256)}.{np.random.randint(1, 256)}"
            url = f"{protocol}://{ip}{path}"
        else:
            url = f"{protocol}://{domain}{path}"
        
        urls.append(url)
        labels.append('phishing')
    
    df = pd.DataFrame({'url': urls, 'label': labels})
    return df


def main():
    """Main function to combine datasets."""
    print("=" * 80)
    print("Combining Phishing Datasets")
    print("=" * 80)
    
    all_data = []
    
    # Look for existing CSV files in datasets folder
    dataset_files = glob.glob('datasets/*.csv') + glob.glob('*.csv')
    dataset_files = [f for f in dataset_files if 'phishing_data.csv' not in f]
    
    if dataset_files:
        print(f"\nFound {len(dataset_files)} dataset files")
        
        for file_path in dataset_files:
            if os.path.exists(file_path):
                df = load_and_process_dataset(file_path)
                if df is not None and len(df) > 0:
                    all_data.append(df)
    
    # Generate synthetic data as fallback or supplement
    print("\nGenerating synthetic training data...")
    synthetic_data = generate_synthetic_data(50000)  # Generate 50k synthetic samples
    all_data.append(synthetic_data)
    
    if not all_data:
        print("No datasets found! Creating synthetic data only...")
        all_data = [generate_synthetic_data(100000)]
    
    # Combine all datasets
    print("\nCombining all datasets...")
    combined_df = pd.concat(all_data, ignore_index=True)
    
    # Remove duplicates
    combined_df = combined_df.drop_duplicates(subset=['url'])
    
    # Shuffle the data
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Filter for valid labels only
    combined_df = combined_df[combined_df['label'].isin(['phishing', 'legitimate'])]
    
    # Save combined dataset
    combined_df.to_csv('phishing_data.csv', index=False)
    
    # Print statistics
    print("\n" + "=" * 80)
    print("Dataset Statistics")
    print("=" * 80)
    print(f"Total samples: {len(combined_df)}")
    print(f"Phishing: {len(combined_df[combined_df['label'] == 'phishing'])}")
    print(f"Legitimate: {len(combined_df[combined_df['label'] == 'legitimate'])}")
    print("\nDataset saved to: phishing_data.csv")
    print("=" * 80)


if __name__ == "__main__":
    main()
