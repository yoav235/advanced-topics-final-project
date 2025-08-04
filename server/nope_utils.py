def sign_message_with_nope(message, sender_id):
    # חתימה מדומה – מוסיפים חתימה פשוטה
    return f"{message}::SIGNED_BY_{sender_id}"

def verify_nope_signature(message, sender_id):
    # אימות מדומה – בודקים שהחתימה מתאימה ל־sender_id
    expected_signature = f"::SIGNED_BY_{sender_id}"
    if message.endswith(expected_signature):
        print(f"[{sender_id}] ✅ NOPE signature verified.")
        return True
    else:
        return False