package recon

import (
	"github.com/google/gousb"
)

type Device struct {
	VendorID      gousb.ID
	ProductID     gousb.ID
	SpecVersion   gousb.BCD
	DeviceVersion gousb.BCD
	Manufacturer  string
	Product       string
}

func GetDevicesInfo() []*Device {
	var result []*Device

	// Initialize a new USB context
	ctx := gousb.NewContext()
	defer ctx.Close()

	// List all connected USB devices
	devices, _ := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		return true
	})

	// Print details for each connected USB device
	for _, device := range devices {
		desc := device.Desc
		manufacturer, _ := device.Manufacturer()
		product, _ := device.Product()
		result = append(result, &Device{
			VendorID:      desc.Vendor,
			ProductID:     desc.Product,
			SpecVersion:   desc.Spec,
			DeviceVersion: desc.Device,
			Manufacturer:  manufacturer,
			Product:       product,
		})
		device.Close()
	}
	return result
}
