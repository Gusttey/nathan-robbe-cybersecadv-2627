using System.ComponentModel.DataAnnotations;

namespace Unbreakable.Models;

// De server bewaart enkel wat hij mag zien: nooit het bericht zelf en nooit een sleutel.
public class Message
{
    public int Id { get; set; }

    [Required]
    [StringLength(40, MinimumLength = 2)]
    [Display(Name = "Van")]
    public string Sender { get; set; }

    [Required]
    [StringLength(40, MinimumLength = 2)]
    [Display(Name = "Aan")]
    public string Recipient { get; set; }

    // De versleutelde tekst, berekend in de browser (modulo 37).
    [Required]
    [StringLength(2000)]
    [Display(Name = "Ciphertext")]
    public string Ciphertext { get; set; }

    // Het nummer van de regel in het codeboek. Dit is niet de sleutel zelf.
    [Display(Name = "Regel in codeboek")]
    public int KeyLine { get; set; }

    // HMAC SHA256 in hexadecimaal, berekend in de browser.
    [Required]
    [StringLength(64)]
    [Display(Name = "MAC")]
    public string Mac { get; set; }

    [Display(Name = "Verzonden")]
    public DateTime SentAt { get; set; }
}
