/*
 * pci-bar-stub: a PCI device that presents a caller-specified BAR layout with no
 * backing storage. Useful for generating or inspecting ACPI tables offline --
 * e.g. reproducing the MMIO windows a passed-through device would create,
 * without the real hardware present.
 *
 * BARs carry no storage (memory_region_init_io with no-op read/write), so a
 * large BAR costs no host RAM; only the BAR *size* matters for BAR assignment
 * and ACPI window generation, and no guest ever executes against it.
 *
 * Properties:
 *   bars="<idx>:<size>:<type>[;<idx>:<size>:<type>...]"   (required)
 *     idx  = BAR index 0-5
 *     size = e.g. 16M, 32M, 128G (decimal + K/M/G suffix)
 *     type = m32 | m64 | p32 | p64   (m=non-prefetchable, p=prefetchable;
 *                                       32/64 = BAR address width)
 *     BARs are ';'-separated so the value survives QEMU's comma property split.
 *   vendor / device / class = PCI IDs (uint16); default to a neutral test
 *     device, override to impersonate a specific device's identity.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "hw/qdev-properties.h"

#define TYPE_PCI_BAR_STUB "pci-bar-stub"
OBJECT_DECLARE_SIMPLE_TYPE(PciBarStub, PCI_BAR_STUB)

struct PciBarStub {
    PCIDevice parent_obj;
    char *bars;
    uint16_t vendor;
    uint16_t device;
    uint16_t class_id;
    MemoryRegion mr[PCI_NUM_REGIONS];
};

static uint64_t pci_bar_stub_parse_size(const char *s)
{
    char *end = NULL;
    uint64_t v = strtoull(s, &end, 0);
    if (end && *end) {
        switch (*end) {
        case 'G': case 'g': v <<= 30; break;
        case 'M': case 'm': v <<= 20; break;
        case 'K': case 'k': v <<= 10; break;
        default: break;
        }
    }
    return v;
}

/* No-op BAR MMIO: ACPI generation never touches guest memory. */
static uint64_t pci_bar_stub_read(void *opaque, hwaddr addr, unsigned size)
{
    return 0;
}
static void pci_bar_stub_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size)
{
}
static const MemoryRegionOps pci_bar_stub_ops = {
    .read = pci_bar_stub_read,
    .write = pci_bar_stub_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void pci_bar_stub_realize(PCIDevice *pdev, Error **errp)
{
    PciBarStub *s = PCI_BAR_STUB(pdev);
    char **specs;

    /* Instance-level identity overrides the neutral class defaults. */
    pci_config_set_vendor_id(pdev->config, s->vendor);
    pci_config_set_device_id(pdev->config, s->device);
    pci_config_set_class(pdev->config, s->class_id);

    if (!s->bars || !s->bars[0]) {
        error_setg(errp, "pci-bar-stub: 'bars' property is required");
        return;
    }

    specs = g_strsplit(s->bars, ";", 0);
    for (int i = 0; specs[i]; i++) {
        char **f = g_strsplit(specs[i], ":", 3);
        if (!f[0] || !f[1] || !f[2]) {
            error_setg(errp, "pci-bar-stub: bad bar spec '%s' "
                       "(want idx:size:type)", specs[i]);
            g_strfreev(f);
            g_strfreev(specs);
            return;
        }
        int idx = (int)strtoul(f[0], NULL, 0);
        uint64_t size = pci_bar_stub_parse_size(f[1]);
        const char *type = f[2];

        if (idx < 0 || idx >= PCI_NUM_REGIONS) {
            error_setg(errp, "pci-bar-stub: bar index %d out of range", idx);
            g_strfreev(f);
            g_strfreev(specs);
            return;
        }

        uint8_t attr = PCI_BASE_ADDRESS_SPACE_MEMORY;
        if (strstr(type, "64")) {
            attr |= PCI_BASE_ADDRESS_MEM_TYPE_64;
        }
        if (type[0] == 'p' || type[0] == 'P') {
            attr |= PCI_BASE_ADDRESS_MEM_PREFETCH;
        }

        char *name = g_strdup_printf("pci-bar-stub-bar%d", idx);
        memory_region_init_io(&s->mr[idx], OBJECT(s), &pci_bar_stub_ops, s,
                              name, size);
        pci_register_bar(pdev, idx, attr, &s->mr[idx]);
        g_free(name);
        g_strfreev(f);
    }
    g_strfreev(specs);
}

static const Property pci_bar_stub_properties[] = {
    DEFINE_PROP_STRING("bars", PciBarStub, bars),
    DEFINE_PROP_UINT16("vendor", PciBarStub, vendor, PCI_VENDOR_ID_REDHAT),
    DEFINE_PROP_UINT16("device", PciBarStub, device, 0x0010),
    DEFINE_PROP_UINT16("class", PciBarStub, class_id, 0x0880),
};

static void pci_bar_stub_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_bar_stub_realize;
    /* Neutral class defaults; realize() applies the instance properties. */
    k->vendor_id = PCI_VENDOR_ID_REDHAT;
    k->device_id = 0x0010;
    k->class_id = 0x0880;              /* system peripheral */
    dc->desc = "PCI device with a caller-specified BAR layout (offline ACPI)";
    device_class_set_props_n(dc, pci_bar_stub_properties,
                             ARRAY_SIZE(pci_bar_stub_properties));
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo pci_bar_stub_info = {
    .name = TYPE_PCI_BAR_STUB,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PciBarStub),
    .class_init = pci_bar_stub_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static void pci_bar_stub_register(void)
{
    type_register_static(&pci_bar_stub_info);
}
type_init(pci_bar_stub_register);
