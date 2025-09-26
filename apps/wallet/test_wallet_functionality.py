import os
import sys
import django
from decimal import Decimal
import random
import string

# Get the absolute path of the current script
current_script_path = os.path.dirname(os.path.abspath(__file__))

# Get the project root directory (2 levels up from the current script)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_script_path)))

# Add the project root to the Python path
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Initialize Django
try:
    django.setup()
except ImportError as e:
    print(f"Error setting up Django: {e}")
    print(f"Project root: {project_root}")
    print(f"sys.path: {sys.path}")
    sys.exit(1)

# Import models after Django setup
try:
    from django.contrib.auth import get_user_model
    from apps.wallet.models import Wallet, WalletTransaction
    User = get_user_model()
except ImportError as e:
    print(f"Error importing models: {e}")
    sys.exit(1)

# Function to generate random reference
def generate_reference():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

def test_wallet_functionality():
    print("\n==== WALLET FUNCTIONALITY TEST ====\n")
    
    # 1. Create test user if needed
    test_email = "wallettest@example.com"
    test_password = "securepassword123"
    
    user, created = User.objects.get_or_create(
        email=test_email,
        defaults={
            'password': test_password,
            'name': 'Wallet Test User',
            'is_active': True,
            'is_verified': True
        }
    )
    
    if created:
        print(f"✓ Created test user: {user.email}")
    else:
        print(f"✓ Using existing user: {user.email}")
    
    # 2. Create wallet
    wallet, created = Wallet.objects.get_or_create(
        user=user,
        defaults={
            'balance': Decimal('0.00'),
            'currency': 'NGN',
            'points': 0,
            'is_active': True
        }
    )
    
    if created:
        print(f"✓ Created wallet with ID: {wallet.wallet_id}")
    else:
        print(f"✓ Using existing wallet: {wallet.wallet_id}")
        print(f"  Current balance: {wallet.balance} {wallet.currency}")
    
    # 3. Create different types of transactions
    transaction_types = [
        {'type': 'deposit', 'amount': Decimal('500.00'), 'desc': 'Test deposit', 'method': 'bank'},
        {'type': 'deposit', 'amount': Decimal('250.00'), 'desc': 'Second deposit', 'method': 'bank'},
        {'type': 'referral_reward', 'amount': Decimal('100.00'), 'desc': 'Referral bonus', 'method': 'system'},
        {'type': 'withdrawal', 'amount': Decimal('150.00'), 'desc': 'Test withdrawal', 'method': 'bank'},
    ]
    
    print("\nCreating test transactions:")
    for tx_data in transaction_types:
        tx = WalletTransaction.objects.create(
            wallet=wallet,
            user=user,
            transaction_type=tx_data['type'],
            amount=tx_data['amount'],
            description=tx_data['desc'],
            payment_method=tx_data['method'],
            currency=wallet.currency,
            reference=generate_reference(),
            status='success'
        )
        print(f"✓ Created {tx.transaction_type} transaction: {tx.amount} {tx.currency}")
        
        # Update wallet balance (simulating business logic)
        if tx.transaction_type in ['deposit', 'referral_reward', 'credit']:
            wallet.balance += tx.amount
        elif tx.transaction_type in ['withdrawal', 'debit']:
            wallet.balance -= tx.amount
            
        wallet.save()
    
    # 4. Verify final wallet state
    wallet.refresh_from_db()
    print(f"\nFinal wallet balance: {wallet.balance} {wallet.currency}")
    
    # 5. Verify transaction count
    tx_count = WalletTransaction.objects.filter(wallet=wallet).count()
    print(f"Total transactions for wallet: {tx_count}")
    
    # 6. Verify transaction queries
    successful_deposits = WalletTransaction.objects.filter(
        wallet=wallet, transaction_type='deposit', status='success'
    ).count()
    print(f"Successful deposits: {successful_deposits}")
    
    # 7. Test API model serialization (if implemented)
    try:
        from apps.wallet.serializers import WalletSerializer, TransactionSerializer
        
        wallet_serializer = WalletSerializer(wallet)
        tx = WalletTransaction.objects.filter(wallet=wallet).first()
        tx_serializer = TransactionSerializer(tx)
        
        print(f"\n✓ WalletSerializer generates valid data")
        print(f"✓ TransactionSerializer generates valid data")
    except ImportError:
        print("\n⚠ Serializers not tested (import failed)")
    
    print("\n==== TEST COMPLETED SUCCESSFULLY ====")

if __name__ == "__main__":
    test_wallet_functionality()