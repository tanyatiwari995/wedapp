/**
 * Utility function to generate WhatsApp links with proper formatting
 * 
 * @param {string} phone - Phone number to send WhatsApp message to
 * @param {string} message - Message to pre-populate in WhatsApp
 * @returns {string} Properly formatted WhatsApp link
 */
export const generateWhatsAppLink = (phone, message) => {
  // Remove any non-numeric characters from phone
  const cleanPhone = phone ? phone.replace(/\D/g, '') : '';
  
  // If phone starts with 0, replace with country code (default to India +91)
  let formattedPhone = cleanPhone;
  if (cleanPhone.startsWith('0')) {
    formattedPhone = `91${cleanPhone.substring(1)}`;
  }
  
  // Handle cases where phone might already have country code
  if (!formattedPhone.startsWith('91') && !formattedPhone.startsWith('+91')) {
    formattedPhone = `91${formattedPhone}`;
  }
  
  // Remove any + symbol
  formattedPhone = formattedPhone.replace('+', '');
  
  // Encode the message for URL
  const encodedMessage = encodeURIComponent(message || '');
  
  // Generate the WhatsApp link
  return `https://wa.me/${formattedPhone}?text=${encodedMessage}`;
};

// Export the function directly for CommonJS compatibility
export default { generateWhatsAppLink };
