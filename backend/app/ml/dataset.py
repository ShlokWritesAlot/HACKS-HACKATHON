import hashlib
import logging
import random
from typing import TypedDict

logger = logging.getLogger(__name__)

class RawSample(TypedDict):
    text: str
    label: str


def group_by_template(samples: list[RawSample]) -> dict[str, list[RawSample]]:
    """
    Groups messages by a locality-sensitive or exact hash to prevent 
    the exact same spam template from appearing in both train and test sets.
    """
    groups = {}
    for sample in samples:
        # A simple content hash. For a real production system, this would be a 
        # MinHash or SimHash to group near-duplicates.
        # Here we strip whitespace and lowercase for a basic exact-match cluster.
        normalized = "".join(sample["text"].split()).lower()
        cluster_id = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        
        if cluster_id not in groups:
            groups[cluster_id] = []
        groups[cluster_id].append(sample)
        
    return groups


def create_leakage_free_splits(
    samples: list[RawSample], test_size: float = 0.2, val_size: float = 0.1
) -> tuple[list[RawSample], list[RawSample], list[RawSample]]:
    """
    Splits dataset into Train, Validation, and Test sets by cluster/template
    rather than by individual message, strictly preventing data leakage.
    """
    groups = group_by_template(samples)
    
    # Shuffle cluster IDs to ensure randomness
    cluster_ids = list(groups.keys())
    random.shuffle(cluster_ids)
    
    total_clusters = len(cluster_ids)
    test_idx = int(total_clusters * (1.0 - test_size))
    val_idx = int(test_idx * (1.0 - (val_size / (1.0 - test_size))))
    
    train_clusters = cluster_ids[:val_idx]
    val_clusters = cluster_ids[val_idx:test_idx]
    test_clusters = cluster_ids[test_idx:]
    
    train_set = []
    for cid in train_clusters:
        train_set.extend(groups[cid])
        
    val_set = []
    for cid in val_clusters:
        val_set.extend(groups[cid])
        
    test_set = []
    for cid in test_clusters:
        test_set.extend(groups[cid])
        
    logger.info(f"Split dataset: {len(train_set)} train, {len(val_set)} val, {len(test_set)} test.")
    return train_set, val_set, test_set
