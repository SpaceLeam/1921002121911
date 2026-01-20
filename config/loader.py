"""
YAML configuration loader for multi-target scanning.
Supports batch scanning with per-target settings.
"""
import yaml
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Load and validate YAML configuration files."""
    
    @staticmethod
    def load(config_file: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            config_file: Path to YAML config file
            
        Returns:
            Dict containing configuration
        """
        config_path = Path(config_file)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            logger.info(f"Loaded config from {config_file}")
            return config
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML syntax: {e}")
            raise
    
    @staticmethod
    def validate_target(target: Dict[str, Any]) -> bool:
        """
        Validate target configuration.
        
        Args:
            target: Target config dict
            
        Returns:
            True if valid
        """
        required_fields = ['name', 'url', 'baseline_payload']
        
        for field in required_fields:
            if field not in target:
                logger.error(f"Missing required field: {field}")
                return False
        
        return True
    
    @staticmethod
    def get_targets(config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract and validate targets from config.
        
        Args:
            config: Full configuration dict
            
        Returns:
            List of validated target configs
        """
        if 'targets' not in config:
            logger.error("No 'targets' section in config")
            return []
        
        targets = config['targets']
        valid_targets = []
        
        for target in targets:
            if ConfigLoader.validate_target(target):
                valid_targets.append(target)
            else:
                logger.warning(f"Skipping invalid target: {target.get('name', 'Unknown')}")
        
        logger.info(f"Loaded {len(valid_targets)} valid targets")
        return valid_targets


def create_sample_config(output_file: str = "config.yaml"):
    """
    Create a sample configuration file.
    
    Args:
        output_file: Output file path
    """
    sample_config = {
        'targets': [
            {
                'name': 'Target A - Production',
                'url': 'https://api-a.com/verify',
                'cookies': 'session=abc123; csrf=xyz',
                'otp_param': 'code',
                'baseline_payload': {
                    'code': '000000',
                    'user_id': '123'
                },
                'rate_limit': 5,  # requests per minute
                'proxy': None
            },
            {
                'name': 'Target B - Staging',
                'url': 'https://staging-b.com/2fa/verify',
                'auth_token': 'Bearer eyJhbGciOi...',
                'otp_param': 'otp',
                'baseline_payload': {
                    'otp': '999999',
                    'email': 'test@test.com'
                },
                'include_race': True,
                'proxy': 'http://127.0.0.1:8080'
            }
        ],
        'global_settings': {
            'output_dir': 'output/',
            'verbose': True,
            'save_requests': True
        }
    }
    
    with open(output_file, 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False, sort_keys=False)
    
    logger.info(f"Sample config created: {output_file}")
    print(f"Sample configuration file created: {output_file}")
