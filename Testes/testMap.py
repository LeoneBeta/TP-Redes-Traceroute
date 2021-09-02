import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import matplotlib.ticker as mticker
import numpy as np

'''
fig = plt.figure(figsize=(16,12))

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

ax.stock_img()

ax.set_extent([-90,-30,10,-40], ccrs.PlateCarree())

states = cfeature.NaturalEarthFeature(category='cultural',
                                    name='admin_1_states_provinces_shp',
                                    scale='50m',
                                    facecolor='none')

ax.add_feature(states, edgecolor='gray', linestyle=':', linewidth=1)


##inserindo as localizações
lon=18
lat=44
ax.scatter(lon,lat,s=50,color='red',zorder=100,transform=ccrs.PlateCarree())



plt.show()