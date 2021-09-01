import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import matplotlib.ticker as mticker
import numpy as np
'''
fig = plt.figure(figsize=(10,8))

ax = fig.add_subplot(111, projection=ccrs.Robinson())

ax.add_feature(cfeature.LAND)
ax.add_feature(cfeature.OCEAN)
ax.add_feature(cfeature.COASTLINE)
ax.add_feature(cfeature.BORDERS)
ax.add_feature(cfeature.LAKES)
ax.add_feature(cfeature.RIVERS)

ax.gridlines(ccrs.Robinson)
ax.set_title('GeoIPLoc',fontsize=20,y=1.02)
'''


##Aproximação mapa Brasil
fig = plt.figure(figsize=(8,6))

ax = fig.add_subplot(111, projection=ccrs.PlateCarree())


ax.add_feature(cfeature.COASTLINE)
ax.add_feature(cfeature.BORDERS)

ax.set_extent([-90,-30,10,-40], ccrs.PlateCarree())

states = cfeature.NaturalEarthFeature(category='cultural',
                                      name='admin_1_states_provinces_shp',
                                      scale='50m',
                                      facecolor='none')

ax.add_feature(states, edgecolor='gray', linestyle=':', linewidth=1)

##inserindo as localizações



##estética
g1 = ax.gridlines(crs=ccrs.PlateCarree(), draw_labels=True, linestyle='--', linewidth=2)

g1.ylabels_right = False
g1.xlabels_top = False

g1.ylocator = mticker.FixedLocator(np.arange(-40,20,10))

ax.stock_img()




plt.show()