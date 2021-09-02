import matplotlib.pyplot as plt

import cartopy.crs as ccrs


def main():
    fig = plt.figure(figsize=(10, 5))
    ax = fig.add_subplot(1, 1, 1, projection=ccrs.Robinson())

    # make the map global rather than have it zoom in to
    # the extents of any plotted data
    ax.set_global()

    ax.stock_img()
    ax.coastlines()

    ax.plot(-0.08, 51.53, 'o', transform=ccrs.PlateCarree())
    ax.plot([-52,-43],[-1,-22], transform=ccrs.PlateCarree())
    ax.plot([-43,-46],[-22,-23], transform=ccrs.PlateCarree())
    ax.plot([-46,-122],[-23,37], transform=ccrs.PlateCarree())

    '''
    [segundo_valorx,segundo_valory],[primeiro_valorx,primeiro_valory]  
    '''


    ##ax.plot([-0.08, 132], [51.53, 43.17], transform=ccrs.Geodetic())

    plt.show()


if __name__ == '__main__':
    main()
