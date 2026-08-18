# Model card

The XGBoost classifier is a laboratory system under assurance. It provides class probabilities needed for error, confidence, and calibration experiments without requiring access to a protected third-party system.

## Intended task

The model classifies synthetic windows as benign, authentication abuse, reconnaissance, lateral movement, or abnormal data transfer.

## Comparison model

Multinomial logistic regression is trained on the same observations. Its results provide context rather than proof that either approach is best for operational deployment.

## Storage and loading

The selected model is stored in native XGBoost JSON. A SHA-256 digest, feature order, class order, seed, dependency versions, and calibration metrics are recorded in the model manifest. Pickle is prohibited.

## Limitations

Synthetic separability may inflate performance. The model has not been tested against public benchmarks, live traffic, adaptive adversaries, protected systems, or a representative cyber range.
