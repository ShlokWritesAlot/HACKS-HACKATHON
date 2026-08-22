"""
Tests for ML Dataset Pipeline (Leakage Prevention).
"""

from app.ml.dataset import RawSample, create_leakage_free_splits, group_by_template


def test_group_by_template():
    """Verify that similar/identical messages are clustered together."""
    samples: list[RawSample] = [
        {"text": "Your OTP is 1234", "label": "BANK_KYC"},
        {"text": " Your OTP is 1234 ", "label": "BANK_KYC"},  # Whitespace diff
        {"text": "your otp is 1234", "label": "BANK_KYC"},  # Case diff
        {"text": "Completely different", "label": "SAFE"},
    ]
    
    groups = group_by_template(samples)
    
    # The first 3 should hash to the exact same cluster
    assert len(groups) == 2
    
    # One cluster has 3 items, one has 1
    cluster_sizes = [len(g) for g in groups.values()]
    assert sorted(cluster_sizes) == [1, 3]


def test_leakage_free_splits():
    """Verify that templates do not cross train/val/test boundaries."""
    # Generate 100 clusters, 3 messages each
    samples = []
    for i in range(100):
        for j in range(3):
            samples.append({"text": f"Template {i} variation {j}", "label": "SAFE"})
            
    train, val, test = create_leakage_free_splits(samples, test_size=0.2, val_size=0.1)
    
    # Sizes should roughly match proportions (since all clusters are size 3, it's exact)
    assert len(train) == 70 * 3  # 70% of 100 clusters
    assert len(val) == 10 * 3   # 10%
    assert len(test) == 20 * 3  # 20%
    
    # Verify absolute zero intersection of templates
    train_clusters = set(group_by_template(train).keys())
    val_clusters = set(group_by_template(val).keys())
    test_clusters = set(group_by_template(test).keys())
    
    assert train_clusters.isdisjoint(val_clusters)
    assert train_clusters.isdisjoint(test_clusters)
    assert val_clusters.isdisjoint(test_clusters)
