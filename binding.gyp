{
  'targets': [
    {
      'target_name': 'hci-ble',
      'type': 'executable',
      'conditions': [
        ['OS=="linux"', {
          'sources': [
            'src/hci-ble.c',
            'src/utility.c'
          ],
          'link_settings': {
            'libraries': [
              '-lbluetooth'
            ]
          }
        }],
        ['OS=="mac"', {
          'sources': [
            'src/dummy.c'
          ]
        }]
      ]
    },
    {
      'target_name': 'l2cap-ble',
      'type': 'executable',
      'conditions': [
        ['OS=="linux"', {
          'sources': [
            'src/l2cap-ble.c',
            'src/utility.c'
          ],
          'link_settings': {
            'libraries': [
              '-lbluetooth'
            ]
          }
        }],
        ['OS=="mac"', {
          'sources': [
            'src/dummy.c'
          ]
        }]
      ]
    }
  ]
}
